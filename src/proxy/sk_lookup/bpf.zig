const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;

const fakedns = @import("../../dns/fakedns.zig");
const config = @import("../../config/mod.zig");
const log = @import("../../log.zig");
const monitoring = @import("../../monitoring.zig");

const linux = std.os.linux;
const BPF = linux.BPF;
const fd_t = std.posix.fd_t;

const af_inet = 2;
const af_inet6 = 10;
const ipproto_tcp = 6;
const sk_pass = 1;
const listener4_key: u32 = 0;
const listener6_key: u32 = 1;
const counter_count = 9;
const max_counter_cpus = 256;

pub const Counter = enum(u32) {
    lookup_hit,
    lookup_miss,
    lookup_expiry,
    assign4_success,
    assign4_error,
    assign6_success,
    assign6_error,
    pass,
    drop,
};

pub const CounterSnapshot = struct {
    values: [counter_count]u64,

    pub fn get(self: CounterSnapshot, counter: Counter) u64 {
        return self.values[@intFromEnum(counter)];
    }
};
const metadata_magic: u64 = 0x585a46444e534d31; // XZFDNSM1
const metadata_schema_version: u32 = 1;
const metadata_header_kind: u16 = 1;
const metadata_lease_kind: u16 = 2;
const metadata_header_family: u32 = 0;
const metadata_family4: u32 = 4;
const metadata_family6: u32 = 6;
const bpf_fs_magic: usize = 0xcafe4a11;
const tmpfs_magic: usize = 0x01021994;
const lock_exclusive = 2;
const lock_nonblocking = 4;
const lock_unlock = 8;
const lock_file_prefix = "xray-zig-fakedns-";
const fake4_pin = "fake4";
const fake6_pin = "fake6";
const metadata_pin = "lease_meta";

const MetadataKey = extern struct {
    family: u32,
    reserved: u32 = 0,
    address: [16]u8,
    domain_id: u64,
    generation: u64,
    route_valid_until_ns: u64,
};

const MetadataValue = extern struct {
    magic: u64,
    config_fingerprint: u64,
    dns_expires_ns: u64,
    schema_version: u32,
    kind: u16,
    domain_len: u16,
    domain: [std.Io.net.HostName.max_len]u8,
    reserved: u8 = 0,
};

const MapInfo = extern struct {
    map_type: u32,
    id: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [16]u8,
    ifindex: u32,
    btf_vmlinux_value_type_id: u32,
    netns_dev: u64,
    netns_ino: u64,
    btf_id: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    alignment_padding: u32,
    map_extra: u64,
};

comptime {
    std.debug.assert(@sizeOf(MetadataKey) == 48);
    std.debug.assert(@sizeOf(MetadataValue) == 288);
    std.debug.assert(@sizeOf(MapInfo) == 88);
}

// Stable UAPI layout of struct bpf_sk_lookup. No kernel BTF is required.
const SkLookupContext = extern struct {
    selected_socket: u64,
    family: u32,
    protocol: u32,
    remote_ip4: u32,
    remote_ip6: [4]u32,
    remote_port_and_padding: u32,
    local_ip4: u32,
    local_ip6: [4]u32,
    local_port: u32,
    ingress_ifindex: u32,
};

comptime {
    std.debug.assert(@offsetOf(SkLookupContext, "protocol") == 12);
    std.debug.assert(@offsetOf(SkLookupContext, "local_ip4") == 40);
    std.debug.assert(@offsetOf(SkLookupContext, "local_ip6") == 44);
}

pub const Dataplane = struct {
    fake4_fd: fd_t,
    fake6_fd: fd_t,
    metadata_fd: ?fd_t,
    listeners_fd: fd_t,
    counters_fd: fd_t,
    counter_cpu_count: usize,
    program_fd: fd_t,
    link_fd: ?fd_t = null,
    persistence_lock_fd: ?fd_t,
    config_fingerprint: u64,

    pub fn init(
        max_entries: u32,
        listener4_fd: fd_t,
        listener6_fd: fd_t,
        fake_dns_cfg: config.FakeDnsConfig,
        persistence: ?config.FakeDnsPersistenceSettings,
        io: Io,
    ) !Dataplane {
        if (builtin.os.tag != .linux) return error.SkLookupRequiresLinux;

        const fingerprint = configFingerprint(fake_dns_cfg, max_entries);
        var persistence_lock_fd: ?fd_t = null;
        errdefer if (persistence_lock_fd) |fd| releasePersistenceLock(fd);

        const maps = if (persistence) |settings| blk: {
            const lock_fd = try acquirePersistenceLock(settings.pin_directory, io);
            persistence_lock_fd = lock_fd;
            var directory = try openPinDirectory(settings.pin_directory, io);
            defer directory.close(io);
            break :blk try openOrCreatePersistentMaps(
                settings.pin_directory,
                directory,
                max_entries,
                fingerprint,
                io,
            );
        } else PersistentMaps{
            .fake4_fd = try createMap(.hash, 4, @sizeOf(fakedns.Publication), max_entries, 0, "xz_fake4"),
            .fake6_fd = undefined,
            .metadata_fd = null,
        };
        errdefer closeFd(maps.fake4_fd);
        var fake6_initialized = persistence != null;
        var owned_maps = maps;
        if (persistence == null) {
            owned_maps.fake6_fd = createMap(.hash, 16, @sizeOf(fakedns.Publication), max_entries, 0, "xz_fake6") catch |err| return err;
            fake6_initialized = true;
        }
        errdefer if (fake6_initialized) closeFd(owned_maps.fake6_fd);
        errdefer if (owned_maps.metadata_fd) |fd| closeFd(fd);
        const listeners_fd = try createMap(.sockmap, @sizeOf(u32), @sizeOf(u32), 2, 0, "xz_listeners");
        errdefer closeFd(listeners_fd);

        const counter_cpu_count = try possibleCpuCount(io);
        const counters_fd = try createMap(.percpu_array, @sizeOf(u32), @sizeOf(u64), counter_count, 0, "xz_sk_count");
        errdefer closeFd(counters_fd);

        try update(listeners_fd, std.mem.asBytes(&listener4_key), std.mem.asBytes(&listener4_fd));
        try update(listeners_fd, std.mem.asBytes(&listener6_key), std.mem.asBytes(&listener6_fd));

        const instructions = program(owned_maps.fake4_fd, owned_maps.fake6_fd, listeners_fd, counters_fd);
        const program_fd = try loadProgram(instructions.slice());
        errdefer closeFd(program_fd);

        return .{
            .fake4_fd = owned_maps.fake4_fd,
            .fake6_fd = owned_maps.fake6_fd,
            .metadata_fd = owned_maps.metadata_fd,
            .listeners_fd = listeners_fd,
            .counters_fd = counters_fd,
            .counter_cpu_count = counter_cpu_count,
            .program_fd = program_fd,
            .persistence_lock_fd = persistence_lock_fd,
            .config_fingerprint = fingerprint,
        };
    }

    pub fn attach(self: *Dataplane, io: Io) !void {
        if (self.link_fd != null) return error.BpfLinkAlreadyAttached;
        var namespace = try Io.Dir.openFileAbsolute(io, "/proc/self/ns/net", .{});
        defer namespace.close(io);
        self.link_fd = try createLink(self.program_fd, namespace.handle);
    }

    pub fn deinit(self: *Dataplane) void {
        if (self.link_fd) |fd| closeFd(fd);
        closeFd(self.program_fd);
        closeFd(self.listeners_fd);
        closeFd(self.counters_fd);
        if (self.metadata_fd) |fd| closeFd(fd);
        closeFd(self.fake6_fd);
        closeFd(self.fake4_fd);
        if (self.persistence_lock_fd) |fd| releasePersistenceLock(fd);
        self.* = undefined;
    }

    pub fn publisher(self: *Dataplane) fakedns.Publisher {
        return .{
            .context = self,
            .publish4_fn = publish4,
            .publish6_fn = publish6,
            .remove4_fn = remove4,
            .remove6_fn = remove6,
            .restore_fn = restore,
        };
    }

    pub fn counterSnapshot(self: *const Dataplane) !CounterSnapshot {
        var snapshot: CounterSnapshot = .{ .values = @splat(0) };
        var per_cpu: [max_counter_cpus]u64 = @splat(0);
        for (0..counter_count) |index| {
            const key: u32 = @intCast(index);
            @memset(per_cpu[0..self.counter_cpu_count], 0);
            _ = try lookup(
                self.counters_fd,
                std.mem.asBytes(&key),
                std.mem.sliceAsBytes(per_cpu[0..self.counter_cpu_count]),
            );
            for (per_cpu[0..self.counter_cpu_count]) |value| snapshot.values[index] +%= value;
        }
        return snapshot;
    }

    fn publish4(context: ?*anyopaque, address: [4]u8, value: fakedns.LeasePublication) !void {
        const self: *Dataplane = @ptrCast(@alignCast(context.?));
        self.publishFamily(metadata_family4, &address, self.fake4_fd, value) catch |err| {
            monitoring.registry.bpfMapUpdate(.ipv4, false);
            return err;
        };
        monitoring.registry.bpfMapUpdate(.ipv4, true);
    }

    fn publish6(context: ?*anyopaque, address: [16]u8, value: fakedns.LeasePublication) !void {
        const self: *Dataplane = @ptrCast(@alignCast(context.?));
        self.publishFamily(metadata_family6, &address, self.fake6_fd, value) catch |err| {
            monitoring.registry.bpfMapUpdate(.ipv6, false);
            return err;
        };
        monitoring.registry.bpfMapUpdate(.ipv6, true);
    }

    fn remove4(context: ?*anyopaque, address: [4]u8) void {
        const self: *Dataplane = @ptrCast(@alignCast(context.?));
        self.removeFamily(metadata_family4, &address, self.fake4_fd);
    }

    fn remove6(context: ?*anyopaque, address: [16]u8) void {
        const self: *Dataplane = @ptrCast(@alignCast(context.?));
        self.removeFamily(metadata_family6, &address, self.fake6_fd);
    }

    fn restore(
        context: ?*anyopaque,
        now_ns: u64,
        visitor_context: ?*anyopaque,
        visitor: fakedns.RestoreVisitor,
    ) !void {
        const self: *Dataplane = @ptrCast(@alignCast(context.?));
        if (self.metadata_fd == null) return;
        try self.restoreFamily(metadata_family4, self.fake4_fd, 4, now_ns, visitor_context, visitor);
        try self.restoreFamily(metadata_family6, self.fake6_fd, 16, now_ns, visitor_context, visitor);
        try self.pruneUnreferencedMetadata();
    }

    fn publishFamily(
        self: *Dataplane,
        family: u32,
        address: []const u8,
        fake_fd: fd_t,
        lease: fakedns.LeasePublication,
    ) !void {
        const metadata_fd = self.metadata_fd orelse {
            try update(fake_fd, address, std.mem.asBytes(&lease.dataplane));
            return;
        };
        if (lease.domain.len == 0 or lease.domain.len > std.Io.net.HostName.max_len)
            return error.InvalidFakeDnsPersistentState;
        const key = metadataKey(family, address, lease.dataplane);
        const value = metadataValue(self.config_fingerprint, lease);
        var previous_metadata: MetadataValue = undefined;
        const had_previous_metadata = lookup(
            metadata_fd,
            std.mem.asBytes(&key),
            std.mem.asBytes(&previous_metadata),
        ) catch |err| switch (err) {
            error.BpfMapKeyNotFound => false,
            else => return err,
        };
        var old: fakedns.Publication = undefined;
        const had_old = lookup(fake_fd, address, std.mem.asBytes(&old)) catch |err| switch (err) {
            error.BpfMapKeyNotFound => false,
            else => return err,
        };

        try update(metadata_fd, std.mem.asBytes(&key), std.mem.asBytes(&value));
        update(fake_fd, address, std.mem.asBytes(&lease.dataplane)) catch |err| {
            if (had_previous_metadata)
                update(metadata_fd, std.mem.asBytes(&key), std.mem.asBytes(&previous_metadata)) catch {}
            else
                delete(metadata_fd, std.mem.asBytes(&key));
            return err;
        };
        if (had_old) {
            const old_key = metadataKey(family, address, old);
            if (!std.meta.eql(old_key, key)) delete(metadata_fd, std.mem.asBytes(&old_key));
        }
    }

    fn removeFamily(self: *Dataplane, family: u32, address: []const u8, fake_fd: fd_t) void {
        var old: fakedns.Publication = undefined;
        const had_old = lookup(fake_fd, address, std.mem.asBytes(&old)) catch false;
        delete(fake_fd, address);
        if (had_old and self.metadata_fd != null) {
            const old_key = metadataKey(family, address, old);
            delete(self.metadata_fd.?, std.mem.asBytes(&old_key));
        }
    }

    fn restoreFamily(
        self: *Dataplane,
        family: u32,
        fake_fd: fd_t,
        key_size: usize,
        now_ns: u64,
        visitor_context: ?*anyopaque,
        visitor: fakedns.RestoreVisitor,
    ) !void {
        var current: [16]u8 = @splat(0);
        var next: [16]u8 = @splat(0);
        var have_current = try getNextKey(fake_fd, null, next[0..key_size]);
        while (have_current) {
            current = next;
            have_current = try getNextKey(fake_fd, current[0..key_size], next[0..key_size]);

            var publication: fakedns.Publication = undefined;
            _ = lookup(fake_fd, current[0..key_size], std.mem.asBytes(&publication)) catch |err| switch (err) {
                error.BpfMapKeyNotFound => continue,
                else => return err,
            };
            const key = metadataKey(family, current[0..key_size], publication);
            var value: MetadataValue = undefined;
            _ = lookup(self.metadata_fd.?, std.mem.asBytes(&key), std.mem.asBytes(&value)) catch |err| switch (err) {
                error.BpfMapKeyNotFound => {
                    delete(fake_fd, current[0..key_size]);
                    continue;
                },
                else => return err,
            };
            try validateLeaseMetadata(value, self.config_fingerprint);
            if (now_ns >= publication.route_valid_until_ns) {
                delete(fake_fd, current[0..key_size]);
                delete(self.metadata_fd.?, std.mem.asBytes(&key));
                continue;
            }
            if (value.dns_expires_ns > publication.route_valid_until_ns)
                return error.IncompatibleBpfPersistence;
            try visitor(visitor_context, .{
                .family = if (family == metadata_family4) .ip4 else .ip6,
                .address = key.address,
                .publication = publication,
                .dns_expires_ns = value.dns_expires_ns,
                .domain = value.domain[0..value.domain_len],
            });
        }
    }

    fn pruneUnreferencedMetadata(self: *Dataplane) !void {
        var current: MetadataKey = std.mem.zeroes(MetadataKey);
        var next: MetadataKey = undefined;
        var have_current = try getNextKey(self.metadata_fd.?, null, std.mem.asBytes(&next));
        while (have_current) {
            current = next;
            have_current = try getNextKey(self.metadata_fd.?, std.mem.asBytes(&current), std.mem.asBytes(&next));
            if (current.family == metadata_header_family) continue;

            var value: MetadataValue = undefined;
            _ = lookup(self.metadata_fd.?, std.mem.asBytes(&current), std.mem.asBytes(&value)) catch |err| switch (err) {
                error.BpfMapKeyNotFound => continue,
                else => return err,
            };
            try validateLeaseMetadata(value, self.config_fingerprint);
            const fake_fd = switch (current.family) {
                metadata_family4 => self.fake4_fd,
                metadata_family6 => self.fake6_fd,
                else => return error.IncompatibleBpfPersistence,
            };
            const address_len: usize = if (current.family == metadata_family4) 4 else 16;
            var publication: fakedns.Publication = undefined;
            const referenced = blk: {
                _ = lookup(fake_fd, current.address[0..address_len], std.mem.asBytes(&publication)) catch |err| switch (err) {
                    error.BpfMapKeyNotFound => break :blk false,
                    else => return err,
                };
                break :blk std.meta.eql(metadataKey(current.family, current.address[0..address_len], publication), current);
            };
            if (!referenced) delete(self.metadata_fd.?, std.mem.asBytes(&current));
        }
    }
};

const PersistentMaps = struct {
    fake4_fd: fd_t,
    fake6_fd: fd_t,
    metadata_fd: ?fd_t,
};

fn createMap(map_type: BPF.MapType, key_size: u32, value_size: u32, max_entries: u32, flags: u32, name: []const u8) !fd_t {
    var attr: BPF.Attr = .{ .map_create = std.mem.zeroes(BPF.MapCreateAttr) };
    attr.map_create.map_type = @intFromEnum(map_type);
    attr.map_create.key_size = key_size;
    attr.map_create.value_size = value_size;
    attr.map_create.max_entries = max_entries;
    attr.map_create.map_flags = flags;
    @memcpy(attr.map_create.map_name[0..name.len], name);
    const rc = linux.bpf(.map_create, &attr, @sizeOf(BPF.MapCreateAttr));
    return fdResult(rc, error.BpfMapCreateFailed);
}

fn lookup(map_fd: fd_t, key: []const u8, value: []u8) !bool {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key.ptr);
    attr.map_elem.result.value = @intFromPtr(value.ptr);
    const rc = linux.bpf(.map_lookup_elem, &attr, @sizeOf(BPF.MapElemAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => true,
        .NOENT => error.BpfMapKeyNotFound,
        else => error.BpfMapLookupFailed,
    };
}

fn getNextKey(map_fd: fd_t, key: ?[]const u8, next_key: []u8) !bool {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = if (key) |bytes| @intFromPtr(bytes.ptr) else 0;
    attr.map_elem.result.next_key = @intFromPtr(next_key.ptr);
    const rc = linux.bpf(.map_get_next_key, &attr, @sizeOf(BPF.MapElemAttr));
    return switch (linux.errno(rc)) {
        .SUCCESS => true,
        .NOENT => false,
        else => error.BpfMapIterationFailed,
    };
}

fn openPinDirectory(path: []const u8, io: Io) !Io.Dir {
    var directory = try Io.Dir.openDirAbsolute(io, path, .{});
    errdefer directory.close(io);
    try requireFileSystem(directory.handle, bpf_fs_magic, error.BpfPersistenceRequiresBpffs);
    return directory;
}

fn acquirePersistenceLock(pin_directory: []const u8, io: Io) !fd_t {
    var run_directory = try Io.Dir.openDirAbsolute(io, "/run", .{});
    defer run_directory.close(io);
    try requireFileSystem(run_directory.handle, tmpfs_magic, error.BpfPersistenceRequiresTmpfsRun);

    var name_buffer: [lock_file_prefix.len + 64 + ".lock".len + 1]u8 = undefined;
    const name = lockFileName(&name_buffer, pin_directory);
    const create_flags: linux.O = .{
        .ACCMODE = .RDWR,
        .CREAT = true,
        .EXCL = true,
        .NOFOLLOW = true,
        .CLOEXEC = true,
    };
    var created = false;
    var rc = linux.openat(run_directory.handle, name.ptr, create_flags, 0o600);
    if (linux.errno(rc) == .EXIST) {
        const existing_flags: linux.O = .{
            .ACCMODE = .RDWR,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        };
        rc = linux.openat(run_directory.handle, name.ptr, existing_flags, 0);
    } else if (linux.errno(rc) == .SUCCESS) {
        created = true;
    }
    if (linux.errno(rc) != .SUCCESS) {
        const errno = linux.errno(rc);
        log.warn("FakeDNS persistence lock open failed: errno={d} ({s})\n", .{ @intFromEnum(errno), @tagName(errno) });
        return error.BpfPersistenceLockOpenFailed;
    }
    const fd: fd_t = @intCast(rc);
    errdefer closeFd(fd);
    if (created and linux.errno(linux.fchmod(fd, 0o600)) != .SUCCESS)
        return error.BpfPersistenceLockModeFailed;
    try validateLockFile(fd);

    const flock_rc = linux.flock(fd, lock_exclusive | lock_nonblocking);
    const flock_errno = linux.errno(flock_rc);
    switch (flock_errno) {
        .SUCCESS => {},
        .AGAIN => return error.BpfPersistenceLocked,
        else => {
            log.warn("FakeDNS persistence flock failed: errno={d} ({s})\n", .{ @intFromEnum(flock_errno), @tagName(flock_errno) });
            return error.BpfPersistenceLockFailed;
        },
    }
    return fd;
}

fn releasePersistenceLock(fd: fd_t) void {
    _ = linux.flock(fd, lock_unlock);
    closeFd(fd);
}

fn requireFileSystem(fd: fd_t, expected_magic: usize, failure: anyerror) !void {
    var stat_buffer: [256]u8 align(@alignOf(usize)) = @splat(0);
    const rc = linux.syscall2(
        .fstatfs,
        @as(usize, @bitCast(@as(isize, fd))),
        @intFromPtr(&stat_buffer),
    );
    if (linux.errno(rc) != .SUCCESS) return error.BpfPersistenceStatFsFailed;
    const fs_type = std.mem.bytesAsValue(usize, stat_buffer[0..@sizeOf(usize)]).*;
    if (fs_type != expected_magic) return failure;
}

fn lockFileName(buffer: []u8, pin_directory: []const u8) [:0]const u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(pin_directory, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.bufPrintZ(buffer, "{s}{s}.lock", .{ lock_file_prefix, &hex }) catch unreachable;
}

fn validateLockFile(fd: fd_t) !void {
    const empty_path: [1:0]u8 = .{0};
    var stat = std.mem.zeroes(linux.Statx);
    const requested: linux.STATX = .{
        .TYPE = true,
        .MODE = true,
        .NLINK = true,
        .UID = true,
        .GID = true,
    };
    const rc = linux.statx(fd, &empty_path, linux.AT.EMPTY_PATH, requested, &stat);
    if (linux.errno(rc) != .SUCCESS) return error.BpfPersistenceLockStatFailed;
    try validateLockStat(stat);
}

fn validateLockStat(stat: linux.Statx) !void {
    if (!linux.S.ISREG(stat.mode) or
        stat.uid != 0 or
        stat.gid != 0 or
        stat.nlink != 1 or
        stat.mode & 0o7777 != 0o600)
    {
        return error.UnsafeBpfPersistenceLockFile;
    }
}

fn openOrCreatePersistentMaps(
    directory_path: []const u8,
    directory: Io.Dir,
    max_entries: u32,
    fingerprint: u64,
    io: Io,
) !PersistentMaps {
    var path4_buffer: [std.posix.PATH_MAX]u8 = undefined;
    var path6_buffer: [std.posix.PATH_MAX]u8 = undefined;
    var metadata_path_buffer: [std.posix.PATH_MAX]u8 = undefined;
    const path4 = try objectPath(&path4_buffer, directory_path, fake4_pin);
    const path6 = try objectPath(&path6_buffer, directory_path, fake6_pin);
    const metadata_path = try objectPath(&metadata_path_buffer, directory_path, metadata_pin);

    const maybe4 = try objectGetOptional(path4, "open fake4");
    errdefer if (maybe4) |fd| closeFd(fd);
    const maybe6 = try objectGetOptional(path6, "open fake6");
    errdefer if (maybe6) |fd| closeFd(fd);
    const maybe_metadata = try objectGetOptional(metadata_path, "open lease_meta");
    errdefer if (maybe_metadata) |fd| closeFd(fd);

    const present_count = @as(u8, if (maybe4 != null) 1 else 0) +
        @as(u8, if (maybe6 != null) 1 else 0) +
        @as(u8, if (maybe_metadata != null) 1 else 0);
    if (present_count == 3) {
        try validatePersistentMapSet(maybe4.?, maybe6.?, maybe_metadata.?, max_entries, fingerprint, true);
        return .{ .fake4_fd = maybe4.?, .fake6_fd = maybe6.?, .metadata_fd = maybe_metadata.? };
    }
    if (present_count != 0) return error.IncompleteBpfPersistence;

    const fake4_fd = try createMap(.hash, 4, @sizeOf(fakedns.Publication), max_entries, 0, "xz_fake4");
    errdefer closeFd(fake4_fd);
    const fake6_fd = try createMap(.hash, 16, @sizeOf(fakedns.Publication), max_entries, 0, "xz_fake6");
    errdefer closeFd(fake6_fd);
    const metadata_fd = try createMap(
        .hash,
        @sizeOf(MetadataKey),
        @sizeOf(MetadataValue),
        metadataMaxEntries(max_entries),
        BPF.BPF_F_NO_PREALLOC,
        "xz_lease_meta",
    );
    errdefer closeFd(metadata_fd);

    const header_key = std.mem.zeroes(MetadataKey);
    const header_value = metadataHeader(fingerprint);
    try update(metadata_fd, std.mem.asBytes(&header_key), std.mem.asBytes(&header_value));

    var pinned4 = false;
    var pinned6 = false;
    var pinned_metadata = false;
    errdefer {
        if (pinned_metadata) directory.deleteFile(io, metadata_pin) catch {};
        if (pinned6) directory.deleteFile(io, fake6_pin) catch {};
        if (pinned4) directory.deleteFile(io, fake4_pin) catch {};
    }
    try objectPin(fake4_fd, path4, "pin fake4");
    pinned4 = true;
    try objectPin(fake6_fd, path6, "pin fake6");
    pinned6 = true;
    try objectPin(metadata_fd, metadata_path, "pin lease_meta");
    pinned_metadata = true;
    return .{ .fake4_fd = fake4_fd, .fake6_fd = fake6_fd, .metadata_fd = metadata_fd };
}

pub fn unpinPersistent(
    settings: config.SkLookupInboundSettings,
    fake_dns_cfg: config.FakeDnsConfig,
    io: Io,
) !void {
    const persistence = settings.fake_dns_persistence orelse return error.FakeDnsPersistenceNotConfigured;
    const lock_fd = try acquirePersistenceLock(persistence.pin_directory, io);
    defer releasePersistenceLock(lock_fd);
    var directory = try openPinDirectory(persistence.pin_directory, io);
    defer directory.close(io);
    const fingerprint = configFingerprint(fake_dns_cfg, settings.max_map_entries);

    var path4_buffer: [std.posix.PATH_MAX]u8 = undefined;
    var path6_buffer: [std.posix.PATH_MAX]u8 = undefined;
    var metadata_path_buffer: [std.posix.PATH_MAX]u8 = undefined;
    const path4 = try objectPath(&path4_buffer, persistence.pin_directory, fake4_pin);
    const path6 = try objectPath(&path6_buffer, persistence.pin_directory, fake6_pin);
    const metadata_path = try objectPath(&metadata_path_buffer, persistence.pin_directory, metadata_pin);
    const maybe4 = try objectGetOptional(path4, "unpin open fake4");
    defer if (maybe4) |fd| closeFd(fd);
    const maybe6 = try objectGetOptional(path6, "unpin open fake6");
    defer if (maybe6) |fd| closeFd(fd);
    const maybe_metadata = try objectGetOptional(metadata_path, "unpin open lease_meta");
    defer if (maybe_metadata) |fd| closeFd(fd);

    if (maybe4) |fd| try validateMap(fd, .hash, 4, @sizeOf(fakedns.Publication), settings.max_map_entries, 0, "xz_fake4");
    if (maybe6) |fd| try validateMap(fd, .hash, 16, @sizeOf(fakedns.Publication), settings.max_map_entries, 0, "xz_fake6");
    if (maybe_metadata) |fd| {
        try validateMap(
            fd,
            .hash,
            @sizeOf(MetadataKey),
            @sizeOf(MetadataValue),
            metadataMaxEntries(settings.max_map_entries),
            BPF.BPF_F_NO_PREALLOC,
            "xz_lease_meta",
        );
        const header_key = std.mem.zeroes(MetadataKey);
        var header: MetadataValue = undefined;
        const has_header = lookup(fd, std.mem.asBytes(&header_key), std.mem.asBytes(&header)) catch |err| switch (err) {
            error.BpfMapKeyNotFound => false,
            else => return err,
        };
        if (has_header) try validateHeader(header, fingerprint);
    }

    if (maybe_metadata != null) try directory.deleteFile(io, metadata_pin);
    if (maybe6 != null) try directory.deleteFile(io, fake6_pin);
    if (maybe4 != null) try directory.deleteFile(io, fake4_pin);
}

fn validatePersistentMapSet(
    fake4_fd: fd_t,
    fake6_fd: fd_t,
    metadata_fd: fd_t,
    max_entries: u32,
    fingerprint: u64,
    require_header: bool,
) !void {
    try validateMap(fake4_fd, .hash, 4, @sizeOf(fakedns.Publication), max_entries, 0, "xz_fake4");
    try validateMap(fake6_fd, .hash, 16, @sizeOf(fakedns.Publication), max_entries, 0, "xz_fake6");
    try validateMap(
        metadata_fd,
        .hash,
        @sizeOf(MetadataKey),
        @sizeOf(MetadataValue),
        metadataMaxEntries(max_entries),
        BPF.BPF_F_NO_PREALLOC,
        "xz_lease_meta",
    );
    const header_key = std.mem.zeroes(MetadataKey);
    var header: MetadataValue = undefined;
    _ = lookup(metadata_fd, std.mem.asBytes(&header_key), std.mem.asBytes(&header)) catch |err| switch (err) {
        error.BpfMapKeyNotFound => if (require_header) return error.IncompatibleBpfPersistence else return,
        else => return err,
    };
    try validateHeader(header, fingerprint);
}

fn validateMap(
    fd: fd_t,
    map_type: BPF.MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
    name: []const u8,
) !void {
    const info = try mapInfo(fd);
    try validateMapInfo(info, map_type, key_size, value_size, max_entries, flags, name);
}

fn validateMapInfo(
    info: MapInfo,
    map_type: BPF.MapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    flags: u32,
    name: []const u8,
) !void {
    const actual_name = std.mem.sliceTo(&info.name, 0);
    if (info.map_type != @intFromEnum(map_type) or
        info.key_size != key_size or
        info.value_size != value_size or
        info.max_entries != max_entries or
        info.map_flags != flags or
        !std.mem.eql(u8, actual_name, name))
    {
        return error.IncompatibleBpfPersistence;
    }
}

fn mapInfo(fd: fd_t) !MapInfo {
    var info = std.mem.zeroes(MapInfo);
    var attr: BPF.Attr = .{ .info = std.mem.zeroes(BPF.InfoAttr) };
    attr.info.bpf_fd = fd;
    attr.info.info_len = @sizeOf(MapInfo);
    attr.info.info = @intFromPtr(&info);
    const rc = linux.bpf(.obj_get_info_by_fd, &attr, @sizeOf(BPF.InfoAttr));
    if (linux.errno(rc) != .SUCCESS) return error.BpfMapInfoFailed;
    if (attr.info.info_len < @offsetOf(MapInfo, "name") + @sizeOf(@TypeOf(info.name)))
        return error.IncompatibleBpfPersistence;
    return info;
}

fn objectGetOptional(path: [:0]const u8, stage: []const u8) !?fd_t {
    var attr: BPF.Attr = .{ .obj = std.mem.zeroes(BPF.ObjAttr) };
    attr.obj.pathname = @intFromPtr(path.ptr);
    const rc = linux.bpf(.obj_get, &attr, @sizeOf(BPF.ObjAttr));
    const errno = linux.errno(rc);
    return switch (errno) {
        .SUCCESS => @intCast(rc),
        .NOENT => null,
        else => {
            log.warn(
                "FakeDNS BPF object get failed: stage={s} path={s} errno={d} ({s})\n",
                .{ stage, path, @intFromEnum(errno), @tagName(errno) },
            );
            return error.BpfObjectGetFailed;
        },
    };
}

fn objectPin(fd: fd_t, path: [:0]const u8, stage: []const u8) !void {
    var attr: BPF.Attr = .{ .obj = std.mem.zeroes(BPF.ObjAttr) };
    attr.obj.pathname = @intFromPtr(path.ptr);
    attr.obj.bpf_fd = fd;
    const rc = linux.bpf(.obj_pin, &attr, @sizeOf(BPF.ObjAttr));
    const errno = linux.errno(rc);
    if (errno != .SUCCESS) {
        log.warn(
            "FakeDNS BPF object pin failed: stage={s} path={s} errno={d} ({s})\n",
            .{ stage, path, @intFromEnum(errno), @tagName(errno) },
        );
        return error.BpfObjectPinFailed;
    }
}

fn objectPath(buffer: []u8, directory: []const u8, name: []const u8) ![:0]const u8 {
    return std.fmt.bufPrintZ(buffer, "{s}/{s}", .{ directory, name }) catch
        error.BpfPinPathTooLong;
}

fn metadataMaxEntries(max_entries: u32) u32 {
    return max_entries * 2 + 2;
}

fn metadataHeader(fingerprint: u64) MetadataValue {
    var value = std.mem.zeroes(MetadataValue);
    value.magic = metadata_magic;
    value.config_fingerprint = fingerprint;
    value.schema_version = metadata_schema_version;
    value.kind = metadata_header_kind;
    return value;
}

fn metadataKey(family: u32, address: []const u8, publication: fakedns.Publication) MetadataKey {
    var key = std.mem.zeroes(MetadataKey);
    key.family = family;
    @memcpy(key.address[0..address.len], address);
    key.domain_id = publication.domain_id;
    key.generation = publication.generation;
    key.route_valid_until_ns = publication.route_valid_until_ns;
    return key;
}

fn metadataValue(fingerprint: u64, lease: fakedns.LeasePublication) MetadataValue {
    var value = std.mem.zeroes(MetadataValue);
    value.magic = metadata_magic;
    value.config_fingerprint = fingerprint;
    value.dns_expires_ns = lease.dns_expires_ns;
    value.schema_version = metadata_schema_version;
    value.kind = metadata_lease_kind;
    value.domain_len = @intCast(lease.domain.len);
    @memcpy(value.domain[0..lease.domain.len], lease.domain);
    return value;
}

fn validateHeader(value: MetadataValue, fingerprint: u64) !void {
    if (value.magic != metadata_magic or
        value.config_fingerprint != fingerprint or
        value.schema_version != metadata_schema_version or
        value.kind != metadata_header_kind or
        value.domain_len != 0)
    {
        return error.IncompatibleBpfPersistence;
    }
}

fn validateLeaseMetadata(value: MetadataValue, fingerprint: u64) !void {
    if (value.magic != metadata_magic or
        value.config_fingerprint != fingerprint or
        value.schema_version != metadata_schema_version or
        value.kind != metadata_lease_kind or
        value.domain_len == 0 or
        value.domain_len > value.domain.len)
    {
        return error.IncompatibleBpfPersistence;
    }
}

fn configFingerprint(fake_dns_cfg: config.FakeDnsConfig, max_entries: u32) u64 {
    var hash: u64 = 0xcbf29ce484222325;
    hashBytes(&hash, "xray-zig-fakedns-bpf");
    hashInteger(&hash, metadata_schema_version);
    hashInteger(&hash, max_entries);
    hashInteger(&hash, fake_dns_cfg.ttl);
    hashInteger(&hash, fake_dns_cfg.reuse_grace_seconds);
    hashBytes(&hash, fake_dns_cfg.ip_pool);
    hashByte(&hash, 0);
    hashBytes(&hash, fake_dns_cfg.ip_pool6);
    return hash;
}

fn hashInteger(hash: *u64, value: u32) void {
    var remaining = value;
    for (0..4) |_| {
        hashByte(hash, @truncate(remaining));
        remaining >>= 8;
    }
}

fn hashBytes(hash: *u64, bytes: []const u8) void {
    for (bytes) |byte| hashByte(hash, byte);
}

fn hashByte(hash: *u64, byte: u8) void {
    hash.* = (hash.* ^ byte) *% 0x100000001b3;
}

fn update(map_fd: fd_t, key: []const u8, value: []const u8) !void {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key.ptr);
    attr.map_elem.result.value = @intFromPtr(value.ptr);
    const rc = linux.bpf(.map_update_elem, &attr, @sizeOf(BPF.MapElemAttr));
    if (linux.errno(rc) != .SUCCESS) return error.BpfMapUpdateFailed;
}

fn delete(map_fd: fd_t, key: []const u8) void {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key.ptr);
    const rc = linux.bpf(.map_delete_elem, &attr, @sizeOf(BPF.MapElemAttr));
    switch (linux.errno(rc)) {
        .SUCCESS, .NOENT => {},
        else => {},
    }
}

fn loadProgram(instructions: []const BPF.Insn) !fd_t {
    var verifier_log: [64 * 1024]u8 = @splat(0);
    const license = "GPL\x00";
    var attr: BPF.Attr = .{ .prog_load = std.mem.zeroes(BPF.ProgLoadAttr) };
    attr.prog_load.prog_type = @intFromEnum(BPF.ProgType.sk_lookup);
    attr.prog_load.insn_cnt = @intCast(instructions.len);
    attr.prog_load.insns = @intFromPtr(instructions.ptr);
    attr.prog_load.license = @intFromPtr(license.ptr);
    attr.prog_load.log_level = 1;
    attr.prog_load.log_size = verifier_log.len;
    attr.prog_load.log_buf = @intFromPtr(&verifier_log);
    attr.prog_load.expected_attach_type = @intFromEnum(BPF.AttachType.sk_lookup);
    const name = "xz_sk_lookup";
    @memcpy(attr.prog_load.prog_name[0..name.len], name);
    const rc = linux.bpf(.prog_load, &attr, @sizeOf(BPF.ProgLoadAttr));
    if (linux.errno(rc) != .SUCCESS) {
        verifier_log[verifier_log.len - 1] = 0;
        const length = std.mem.indexOfScalar(u8, &verifier_log, 0) orelse verifier_log.len;
        log.warn("SK_LOOKUP BPF verifier rejected program: {s}\n", .{verifier_log[0..length]});
        return error.BpfProgramLoadFailed;
    }
    return @intCast(rc);
}

fn createLink(program_fd: fd_t, namespace_fd: fd_t) !fd_t {
    var attr: BPF.Attr = .{ .link_create = std.mem.zeroes(BPF.LinkCreateAttr) };
    attr.link_create.prog_fd = program_fd;
    attr.link_create.target_fd = namespace_fd;
    attr.link_create.attach_type = @intFromEnum(BPF.AttachType.sk_lookup);
    const rc = linux.bpf(.link_create, &attr, @sizeOf(BPF.LinkCreateAttr));
    return fdResult(rc, error.BpfLinkCreateFailed);
}

fn fdResult(rc: usize, failure: anyerror) !fd_t {
    if (linux.errno(rc) != .SUCCESS) return failure;
    return @intCast(rc);
}

fn closeFd(fd: fd_t) void {
    _ = linux.close(fd);
}

fn possibleCpuCount(io: Io) !usize {
    var file = try Io.Dir.openFileAbsolute(io, "/sys/devices/system/cpu/possible", .{});
    defer file.close(io);
    var buffer: [128]u8 = undefined;
    const len = try file.readStreaming(io, &.{&buffer});
    if (len == 0 or len == buffer.len) return error.InvalidPossibleCpuList;
    return parsePossibleCpuCount(std.mem.trim(u8, buffer[0..len], " \t\r\n"));
}

fn parsePossibleCpuCount(text: []const u8) !usize {
    var count: usize = 0;
    var ranges = std.mem.splitScalar(u8, text, ',');
    while (ranges.next()) |range| {
        if (range.len == 0) return error.InvalidPossibleCpuList;
        if (std.mem.indexOfScalar(u8, range, '-')) |dash| {
            const first = std.fmt.parseUnsigned(usize, range[0..dash], 10) catch
                return error.InvalidPossibleCpuList;
            const last = std.fmt.parseUnsigned(usize, range[dash + 1 ..], 10) catch
                return error.InvalidPossibleCpuList;
            if (last < first) return error.InvalidPossibleCpuList;
            count = std.math.add(usize, count, last - first + 1) catch
                return error.UnsupportedBpfCounterCpuCount;
        } else {
            _ = std.fmt.parseUnsigned(usize, range, 10) catch
                return error.InvalidPossibleCpuList;
            count = std.math.add(usize, count, 1) catch
                return error.UnsupportedBpfCounterCpuCount;
        }
    }
    if (count == 0 or count > max_counter_cpus) return error.UnsupportedBpfCounterCpuCount;
    return count;
}

const Program = struct {
    instructions: [192]BPF.Insn = undefined,
    len: usize = 0,

    fn emit(self: *Program, instruction: BPF.Insn) usize {
        std.debug.assert(self.len < self.instructions.len);
        const index = self.len;
        self.instructions[index] = instruction;
        self.len += 1;
        return index;
    }

    fn patch(self: *Program, jump_index: usize, target_index: usize) void {
        const distance = @as(isize, @intCast(target_index)) - @as(isize, @intCast(jump_index)) - 1;
        self.instructions[jump_index].off = @intCast(distance);
    }

    fn slice(self: *const Program) []const BPF.Insn {
        return self.instructions[0..self.len];
    }
};

fn emitCounter(result: *Program, counters_fd: fd_t, counter: Counter) void {
    _ = result.emit(BPF.Insn.st(.word, .r10, -24, @intCast(@intFromEnum(counter))));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, counters_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(counters_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -24));
    _ = result.emit(BPF.Insn.call(.map_lookup_elem));
    _ = result.emit(BPF.Insn.jeq(.r0, 0, 2));
    _ = result.emit(BPF.Insn.mov(.r1, 1));
    _ = result.emit(BPF.Insn.xadd(.r0, .r1));
}

fn program(fake4_fd: fd_t, fake6_fd: fd_t, listeners_fd: fd_t, counters_fd: fd_t) Program {
    var result: Program = .{};
    _ = result.emit(BPF.Insn.mov(.r6, .r1));
    _ = result.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "protocol")));
    const non_tcp_jump = result.emit(BPF.Insn.jne(.r2, ipproto_tcp, 0));
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "family")));
    const ipv4_jump = result.emit(BPF.Insn.jeq(.r2, af_inet, 0));
    const unknown_family_jump = result.emit(BPF.Insn.jne(.r2, af_inet6, 0));

    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip6")));
    _ = result.emit(BPF.Insn.stx(.word, .r10, -16, .r2));
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip6") + 4));
    _ = result.emit(BPF.Insn.stx(.word, .r10, -12, .r2));
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip6") + 8));
    _ = result.emit(BPF.Insn.stx(.word, .r10, -8, .r2));
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip6") + 12));
    _ = result.emit(BPF.Insn.stx(.word, .r10, -4, .r2));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, fake6_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(fake6_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -16));
    _ = result.emit(BPF.Insn.call(.map_lookup_elem));
    const ipv6_miss_jump = result.emit(BPF.Insn.jeq(.r0, 0, 0));
    _ = result.emit(BPF.Insn.mov(.r7, .r0));
    _ = result.emit(BPF.Insn.call(.ktime_get_ns));
    _ = result.emit(BPF.Insn.ldx(.double_word, .r8, .r7, 16));
    const ipv6_expiry_jump = result.emit(BPF.Insn.jge(.r0, .r8, 0));
    emitCounter(&result, counters_fd, .lookup_hit);
    _ = result.emit(BPF.Insn.st(.word, .r10, -20, listener6_key));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, listeners_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(listeners_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -20));
    _ = result.emit(BPF.Insn.call(.map_lookup_elem));
    const ipv6_listener_miss_jump = result.emit(BPF.Insn.jeq(.r0, 0, 0));
    _ = result.emit(BPF.Insn.mov(.r7, .r0));
    _ = result.emit(BPF.Insn.mov(.r1, .r6));
    _ = result.emit(BPF.Insn.mov(.r2, .r7));
    _ = result.emit(BPF.Insn.mov(.r3, 0));
    _ = result.emit(BPF.Insn.call(.sk_assign));
    _ = result.emit(BPF.Insn.mov(.r8, .r0));
    _ = result.emit(BPF.Insn.mov(.r1, .r7));
    _ = result.emit(BPF.Insn.call(.sk_release));
    const ipv6_assign_error_jump = result.emit(BPF.Insn.jne(.r8, 0, 0));
    emitCounter(&result, counters_fd, .assign6_success);
    const ipv6_success_exit_jump = result.emit(BPF.Insn.ja(0));
    const ipv6_assign_error = result.len;
    emitCounter(&result, counters_fd, .assign6_error);
    const ipv6_error_exit_jump = result.emit(BPF.Insn.ja(0));

    const ipv4_start = result.len;
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip4")));
    _ = result.emit(BPF.Insn.stx(.word, .r10, -4, .r2));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, fake4_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(fake4_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -4));
    _ = result.emit(BPF.Insn.call(.map_lookup_elem));
    const ipv4_miss_jump = result.emit(BPF.Insn.jeq(.r0, 0, 0));
    _ = result.emit(BPF.Insn.mov(.r7, .r0));
    _ = result.emit(BPF.Insn.call(.ktime_get_ns));
    _ = result.emit(BPF.Insn.ldx(.double_word, .r8, .r7, 16));
    const ipv4_expiry_jump = result.emit(BPF.Insn.jge(.r0, .r8, 0));
    emitCounter(&result, counters_fd, .lookup_hit);
    _ = result.emit(BPF.Insn.st(.word, .r10, -20, listener4_key));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, listeners_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(listeners_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -20));
    _ = result.emit(BPF.Insn.call(.map_lookup_elem));
    const ipv4_listener_miss_jump = result.emit(BPF.Insn.jeq(.r0, 0, 0));
    _ = result.emit(BPF.Insn.mov(.r7, .r0));
    _ = result.emit(BPF.Insn.mov(.r1, .r6));
    _ = result.emit(BPF.Insn.mov(.r2, .r7));
    _ = result.emit(BPF.Insn.mov(.r3, 0));
    _ = result.emit(BPF.Insn.call(.sk_assign));
    _ = result.emit(BPF.Insn.mov(.r8, .r0));
    _ = result.emit(BPF.Insn.mov(.r1, .r7));
    _ = result.emit(BPF.Insn.call(.sk_release));
    const ipv4_assign_error_jump = result.emit(BPF.Insn.jne(.r8, 0, 0));
    emitCounter(&result, counters_fd, .assign4_success);
    const ipv4_success_exit_jump = result.emit(BPF.Insn.ja(0));
    const ipv4_assign_error = result.len;
    emitCounter(&result, counters_fd, .assign4_error);
    const ipv4_error_exit_jump = result.emit(BPF.Insn.ja(0));

    const lookup_miss = result.len;
    emitCounter(&result, counters_fd, .lookup_miss);
    const miss_exit_jump = result.emit(BPF.Insn.ja(0));
    const lookup_expiry = result.len;
    emitCounter(&result, counters_fd, .lookup_expiry);
    const exit_index = result.len;
    emitCounter(&result, counters_fd, .pass);
    _ = result.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = result.emit(BPF.Insn.exit());

    result.patch(non_tcp_jump, exit_index);
    result.patch(ipv4_jump, ipv4_start);
    result.patch(unknown_family_jump, exit_index);
    result.patch(ipv6_miss_jump, lookup_miss);
    result.patch(ipv6_expiry_jump, lookup_expiry);
    result.patch(ipv6_listener_miss_jump, ipv6_assign_error);
    result.patch(ipv6_assign_error_jump, ipv6_assign_error);
    result.patch(ipv6_success_exit_jump, exit_index);
    result.patch(ipv6_error_exit_jump, exit_index);
    result.patch(ipv4_miss_jump, lookup_miss);
    result.patch(ipv4_expiry_jump, lookup_expiry);
    result.patch(ipv4_listener_miss_jump, ipv4_assign_error);
    result.patch(ipv4_assign_error_jump, ipv4_assign_error);
    result.patch(ipv4_success_exit_jump, exit_index);
    result.patch(ipv4_error_exit_jump, exit_index);
    result.patch(miss_exit_jump, exit_index);
    return result;
}

test "SK_LOOKUP program has stable UAPI-only instruction layout" {
    const generated = program(10, 11, 12, 13);
    const instructions = generated.slice();
    var assign_count: usize = 0;
    var release_count: usize = 0;
    var counter_updates: usize = 0;
    for (instructions) |instruction| {
        if (std.meta.eql(BPF.Insn.call(.sk_assign), instruction)) assign_count += 1;
        if (std.meta.eql(BPF.Insn.call(.sk_release), instruction)) release_count += 1;
        if (std.meta.eql(BPF.Insn.xadd(.r0, .r1), instruction)) counter_updates += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), assign_count);
    try std.testing.expectEqual(@as(usize, 2), release_count);
    try std.testing.expectEqual(@as(usize, 9), counter_updates);
    try std.testing.expectEqual(BPF.Insn.exit(), instructions[instructions.len - 1]);
}

test "possible CPU list parser bounds per-CPU snapshots" {
    try std.testing.expectEqual(@as(usize, 4), try parsePossibleCpuCount("0-3"));
    try std.testing.expectEqual(@as(usize, 6), try parsePossibleCpuCount("0-3,8,10"));
    try std.testing.expectError(error.InvalidPossibleCpuList, parsePossibleCpuCount("3-1"));
    try std.testing.expectError(error.UnsupportedBpfCounterCpuCount, parsePossibleCpuCount("0-256"));
}

test "FakeDNS persistence schema validates exact map ABI" {
    var info = std.mem.zeroes(MapInfo);
    info.map_type = @intFromEnum(BPF.MapType.hash);
    info.key_size = @sizeOf(MetadataKey);
    info.value_size = @sizeOf(MetadataValue);
    info.max_entries = metadataMaxEntries(64);
    info.map_flags = BPF.BPF_F_NO_PREALLOC;
    @memcpy(info.name[0.."xz_lease_meta".len], "xz_lease_meta");
    try validateMapInfo(
        info,
        .hash,
        @sizeOf(MetadataKey),
        @sizeOf(MetadataValue),
        metadataMaxEntries(64),
        BPF.BPF_F_NO_PREALLOC,
        "xz_lease_meta",
    );
    info.value_size -= 1;
    try std.testing.expectError(error.IncompatibleBpfPersistence, validateMapInfo(
        info,
        .hash,
        @sizeOf(MetadataKey),
        @sizeOf(MetadataValue),
        metadataMaxEntries(64),
        BPF.BPF_F_NO_PREALLOC,
        "xz_lease_meta",
    ));
}

test "FakeDNS persistence header fails closed on schema or config mismatch" {
    const cfg: config.FakeDnsConfig = .{
        .ip_pool = "198.18.0.0/15",
        .ip_pool6 = "fc00::/18",
        .ttl = 60,
        .reuse_grace_seconds = 30,
    };
    const fingerprint = configFingerprint(cfg, 1024);
    const header = metadataHeader(fingerprint);
    try validateHeader(header, fingerprint);

    var wrong_schema = header;
    wrong_schema.schema_version += 1;
    try std.testing.expectError(error.IncompatibleBpfPersistence, validateHeader(wrong_schema, fingerprint));
    try std.testing.expectError(error.IncompatibleBpfPersistence, validateHeader(header, fingerprint + 1));

    var changed = cfg;
    changed.ttl += 1;
    try std.testing.expect(fingerprint != configFingerprint(changed, 1024));
    changed = cfg;
    changed.reuse_grace_seconds += 1;
    try std.testing.expect(fingerprint != configFingerprint(changed, 1024));
    changed = cfg;
    changed.ip_pool = "198.19.0.0/16";
    try std.testing.expect(fingerprint != configFingerprint(changed, 1024));
    try std.testing.expect(fingerprint != configFingerprint(cfg, 1025));
}

test "FakeDNS metadata keys preserve old and pending transaction versions" {
    const address = [_]u8{ 198, 18, 0, 1 };
    const old: fakedns.Publication = .{ .domain_id = 1, .generation = 1, .route_valid_until_ns = 100 };
    const refresh: fakedns.Publication = .{ .domain_id = 1, .generation = 1, .route_valid_until_ns = 200 };
    const reused: fakedns.Publication = .{ .domain_id = 2, .generation = 2, .route_valid_until_ns = 300 };
    const old_key = metadataKey(metadata_family4, &address, old);
    const refresh_key = metadataKey(metadata_family4, &address, refresh);
    const reused_key = metadataKey(metadata_family4, &address, reused);
    try std.testing.expect(!std.meta.eql(old_key, refresh_key));
    try std.testing.expect(!std.meta.eql(old_key, reused_key));
    try std.testing.expect(std.meta.eql(refresh_key, metadataKey(metadata_family4, &address, refresh)));
    try std.testing.expectEqual(@as(u32, 130), metadataMaxEntries(64));
}

test "FakeDNS persistence lock name is deterministic and path-specific" {
    var first_buffer: [lock_file_prefix.len + 64 + ".lock".len + 1]u8 = undefined;
    var second_buffer: [lock_file_prefix.len + 64 + ".lock".len + 1]u8 = undefined;
    const first = lockFileName(&first_buffer, "/sys/fs/bpf/xray-zig");
    const second = lockFileName(&second_buffer, "/sys/fs/bpf/other");
    try std.testing.expectEqualStrings(
        "xray-zig-fakedns-c7688eb4a2590909688796b515cc00998a0b496e2354fc5008f1076c5ecbfb42.lock",
        first,
    );
    try std.testing.expect(!std.mem.eql(u8, first, second));
}

test "FakeDNS persistence accepts only a private root lock file" {
    var stat = std.mem.zeroes(linux.Statx);
    stat.mode = linux.S.IFREG | 0o600;
    stat.uid = 0;
    stat.gid = 0;
    stat.nlink = 1;
    try validateLockStat(stat);

    stat.uid = 1000;
    try std.testing.expectError(error.UnsafeBpfPersistenceLockFile, validateLockStat(stat));
    stat.uid = 0;
    stat.mode = linux.S.IFREG | 0o640;
    try std.testing.expectError(error.UnsafeBpfPersistenceLockFile, validateLockStat(stat));
    stat.mode = linux.S.IFDIR | 0o600;
    try std.testing.expectError(error.UnsafeBpfPersistenceLockFile, validateLockStat(stat));
}
