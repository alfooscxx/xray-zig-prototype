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
const admission_capacity = 4096;
const admission_validity_ns = 60 * std.time.ns_per_s;
const fake_handler_index: u32 = 0;
const literal_handler_index: u32 = 1;

const AdmissionKey = extern struct {
    family: u32,
    remote_address: [16]u8,
    local_address: [16]u8,
    remote_port: u16,
    remote_port_padding: u16,
    local_port: u32,
};

comptime {
    std.debug.assert(@offsetOf(SkLookupContext, "selected_socket") == 0);
    std.debug.assert(@sizeOf(AdmissionKey) == 44);
}

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
    excluded4_fd: fd_t,
    excluded6_fd: fd_t,
    admissions_fd: fd_t,
    programs_fd: fd_t,
    counter_cpu_count: usize,
    program_fd: fd_t,
    fake_program_fd: fd_t,
    literal_program_fd: fd_t,
    link_fd: ?fd_t = null,
    persistence_lock_fd: ?fd_t,
    config_fingerprint: u64,

    pub fn init(
        max_entries: u32,
        listener4_fd: fd_t,
        listener6_fd: fd_t,
        fake_dns_cfg: config.FakeDnsConfig,
        persistence: ?config.FakeDnsPersistenceSettings,
        transparent: ?config.TransparentInterceptSettings,
        transparent_ifindex: ?u32,
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
        const exclusion_capacity: u32 = if (transparent) |settings|
            @intCast(@max(@as(usize, 2), settings.excluded_ips.len + settings.proxy_server_ips.len + 2))
        else
            2;
        const excluded4_fd = try createMap(.lpm_trie, 8, 1, exclusion_capacity, 1, "xz_exclude4");
        errdefer closeFd(excluded4_fd);
        const excluded6_fd = try createMap(.lpm_trie, 20, 1, exclusion_capacity, 1, "xz_exclude6");
        errdefer closeFd(excluded6_fd);
        const admissions_fd = try createMap(.lru_hash, @sizeOf(AdmissionKey), @sizeOf(u64), admission_capacity, 0, "xz_admit");
        errdefer closeFd(admissions_fd);
        if (transparent) |settings| try populateExclusions(excluded4_fd, excluded6_fd, fake_dns_cfg, settings);

        try update(listeners_fd, std.mem.asBytes(&listener4_key), std.mem.asBytes(&listener4_fd));
        try update(listeners_fd, std.mem.asBytes(&listener6_key), std.mem.asBytes(&listener6_fd));

        const programs_fd = try createMap(.prog_array, @sizeOf(u32), @sizeOf(u32), 2, 0, "xz_sk_progs");
        errdefer closeFd(programs_fd);
        const fake_instructions = fakeProgram(owned_maps.fake4_fd, owned_maps.fake6_fd, listeners_fd, counters_fd, programs_fd, transparent_ifindex != null);
        const fake_program_fd = try loadProgram(fake_instructions.slice(), "xz_sk_fake");
        errdefer closeFd(fake_program_fd);
        const literal_instructions = literalProgram(listeners_fd, counters_fd, excluded4_fd, excluded6_fd, admissions_fd, transparent_ifindex);
        const literal_program_fd = try loadProgram(literal_instructions.slice(), "xz_sk_literal");
        errdefer closeFd(literal_program_fd);
        try update(programs_fd, std.mem.asBytes(&fake_handler_index), std.mem.asBytes(&fake_program_fd));
        try update(programs_fd, std.mem.asBytes(&literal_handler_index), std.mem.asBytes(&literal_program_fd));
        const instructions = dispatcherProgram(programs_fd);
        const program_fd = try loadProgram(instructions.slice(), "xz_sk_lookup");
        errdefer closeFd(program_fd);

        return .{
            .fake4_fd = owned_maps.fake4_fd,
            .fake6_fd = owned_maps.fake6_fd,
            .metadata_fd = owned_maps.metadata_fd,
            .listeners_fd = listeners_fd,
            .counters_fd = counters_fd,
            .excluded4_fd = excluded4_fd,
            .excluded6_fd = excluded6_fd,
            .admissions_fd = admissions_fd,
            .programs_fd = programs_fd,
            .counter_cpu_count = counter_cpu_count,
            .program_fd = program_fd,
            .fake_program_fd = fake_program_fd,
            .literal_program_fd = literal_program_fd,
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
        closeFd(self.literal_program_fd);
        closeFd(self.fake_program_fd);
        closeFd(self.programs_fd);
        closeFd(self.listeners_fd);
        closeFd(self.counters_fd);
        closeFd(self.excluded6_fd);
        closeFd(self.excluded4_fd);
        closeFd(self.admissions_fd);
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

    pub fn consumeLiteralAdmission(self: *const Dataplane, local: std.Io.net.IpAddress, remote: std.Io.net.IpAddress, now_ns: u64) bool {
        const key = admissionKey(local, remote) orelse return false;
        var admitted_at_ns: u64 = 0;
        const found = lookup(self.admissions_fd, std.mem.asBytes(&key), std.mem.asBytes(&admitted_at_ns)) catch return false;
        if (!found) return false;
        delete(self.admissions_fd, std.mem.asBytes(&key));
        return admissionFresh(admitted_at_ns, now_ns);
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

fn populateExclusions(fake4_fd: fd_t, fake6_fd: fd_t, fake_dns_cfg: config.FakeDnsConfig, settings: config.TransparentInterceptSettings) !void {
    try addExclusionText(fake4_fd, fake6_fd, fake_dns_cfg.ip_pool);
    try addExclusionText(fake4_fd, fake6_fd, fake_dns_cfg.ip_pool6);
    for (settings.excluded_ips) |rule| try addExclusion(fake4_fd, fake6_fd, rule);
    for (settings.proxy_server_ips) |rule| try addExclusion(fake4_fd, fake6_fd, rule);
}

fn addExclusionText(fake4_fd: fd_t, fake6_fd: fd_t, source: []const u8) !void {
    const slash = std.mem.indexOfScalar(u8, source, '/') orelse return error.InvalidFakeDnsPool;
    const address = std.Io.net.IpAddress.parse(source[0..slash], 0) catch return error.InvalidFakeDnsPool;
    const prefix = std.fmt.parseUnsigned(u8, source[slash + 1 ..], 10) catch return error.InvalidFakeDnsPool;
    switch (address) {
        .ip4 => |ip| {
            if (prefix > 32) return error.InvalidFakeDnsPool;
            try addExclusion(fake4_fd, fake6_fd, .{ .ip4 = .{ .bytes = ip.bytes, .prefix_len = prefix } });
        },
        .ip6 => |ip| {
            if (prefix > 128) return error.InvalidFakeDnsPool;
            try addExclusion(fake4_fd, fake6_fd, .{ .ip6 = .{ .bytes = ip.bytes, .prefix_len = prefix } });
        },
    }
}

fn addExclusion(fake4_fd: fd_t, fake6_fd: fd_t, rule: config.IpRule) !void {
    const value: u8 = 1;
    switch (rule) {
        .ip4 => |cidr| {
            var key: [8]u8 = @splat(0);
            std.mem.writeInt(u32, key[0..4], cidr.prefix_len, .native);
            @memcpy(key[4..8], &cidr.bytes);
            try update(fake4_fd, &key, std.mem.asBytes(&value));
        },
        .ip6 => |cidr| {
            var key: [20]u8 = @splat(0);
            std.mem.writeInt(u32, key[0..4], cidr.prefix_len, .native);
            @memcpy(key[4..20], &cidr.bytes);
            try update(fake6_fd, &key, std.mem.asBytes(&value));
        },
    }
}

fn admissionKey(local: std.Io.net.IpAddress, remote: std.Io.net.IpAddress) ?AdmissionKey {
    var key: AdmissionKey = .{
        .family = 0,
        .remote_address = @splat(0),
        .local_address = @splat(0),
        .remote_port = 0,
        .remote_port_padding = 0,
        .local_port = local.getPort(),
    };
    switch (local) {
        .ip4 => |local4| switch (remote) {
            .ip4 => |remote4| {
                key.family = af_inet;
                @memcpy(key.local_address[0..4], &local4.bytes);
                @memcpy(key.remote_address[0..4], &remote4.bytes);
            },
            .ip6 => return null,
        },
        .ip6 => |local6| switch (remote) {
            .ip4 => return null,
            .ip6 => |remote6| {
                key.family = af_inet6;
                key.local_address = local6.bytes;
                key.remote_address = remote6.bytes;
            },
        },
    }
    key.remote_port = std.mem.nativeToBig(u16, remote.getPort());
    return key;
}

fn admissionFresh(admitted_at_ns: u64, now_ns: u64) bool {
    return admitted_at_ns != 0 and now_ns >= admitted_at_ns and now_ns - admitted_at_ns <= admission_validity_ns;
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

fn loadProgram(instructions: []const BPF.Insn, name: []const u8) !fd_t {
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
    instructions: [384]BPF.Insn = undefined,
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

fn emitAdmission(result: *Program, admissions_fd: fd_t, comptime family: std.Io.net.IpAddress.Family) void {
    for (0..11) |index| _ = result.emit(BPF.Insn.st(.word, .r10, @intCast(-80 + @as(i32, @intCast(index * 4))), 0));
    _ = result.emit(BPF.Insn.st(.word, .r10, -80, if (family == .ip4) af_inet else af_inet6));
    const words: usize = if (family == .ip4) 1 else 4;
    const remote_offset = if (family == .ip4) @offsetOf(SkLookupContext, "remote_ip4") else @offsetOf(SkLookupContext, "remote_ip6");
    const local_offset = if (family == .ip4) @offsetOf(SkLookupContext, "local_ip4") else @offsetOf(SkLookupContext, "local_ip6");
    for (0..words) |index| {
        _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @intCast(remote_offset + index * 4)));
        _ = result.emit(BPF.Insn.stx(.word, .r10, @intCast(-76 + @as(i32, @intCast(index * 4))), .r2));
        _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @intCast(local_offset + index * 4)));
        _ = result.emit(BPF.Insn.stx(.word, .r10, @intCast(-60 + @as(i32, @intCast(index * 4))), .r2));
    }
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "remote_port_and_padding")));
    _ = result.emit(BPF.Insn.stx(.word, .r10, -44, .r2));
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_port")));
    _ = result.emit(BPF.Insn.stx(.word, .r10, -40, .r2));
    _ = result.emit(BPF.Insn.call(.ktime_get_ns));
    _ = result.emit(BPF.Insn.stx(.double_word, .r10, -88, .r0));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, admissions_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(admissions_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -80));
    _ = result.emit(BPF.Insn.mov(.r3, .r10));
    _ = result.emit(BPF.Insn.add(.r3, -88));
    _ = result.emit(BPF.Insn.mov(.r4, 0));
    _ = result.emit(BPF.Insn.call(.map_update_elem));
}

const AssignExits = struct { success: usize, failure: usize };

fn emitLiteralAssign(result: *Program, listeners_fd: fd_t, counters_fd: fd_t, admissions_fd: fd_t, comptime family: std.Io.net.IpAddress.Family) AssignExits {
    const listener_key = if (family == .ip4) listener4_key else listener6_key;
    const success_counter: Counter = if (family == .ip4) .assign4_success else .assign6_success;
    const error_counter: Counter = if (family == .ip4) .assign4_error else .assign6_error;
    _ = result.emit(BPF.Insn.st(.word, .r10, -20, listener_key));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, listeners_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(listeners_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -20));
    _ = result.emit(BPF.Insn.call(.map_lookup_elem));
    const listener_miss = result.emit(BPF.Insn.jeq(.r0, 0, 0));
    _ = result.emit(BPF.Insn.mov(.r7, .r0));
    _ = result.emit(BPF.Insn.mov(.r1, .r6));
    _ = result.emit(BPF.Insn.mov(.r2, .r7));
    _ = result.emit(BPF.Insn.mov(.r3, 0));
    _ = result.emit(BPF.Insn.call(.sk_assign));
    _ = result.emit(BPF.Insn.mov(.r8, .r0));
    _ = result.emit(BPF.Insn.mov(.r1, .r7));
    _ = result.emit(BPF.Insn.call(.sk_release));
    const assign_error = result.emit(BPF.Insn.jne(.r8, 0, 0));
    emitAdmission(result, admissions_fd, family);
    emitCounter(result, counters_fd, success_counter);
    const success_exit = result.emit(BPF.Insn.ja(0));
    const error_block = result.len;
    emitCounter(result, counters_fd, error_counter);
    const error_exit = result.emit(BPF.Insn.ja(0));
    result.patch(listener_miss, error_block);
    result.patch(assign_error, error_block);
    return .{ .success = success_exit, .failure = error_exit };
}

fn emitFakeAssign(result: *Program, listeners_fd: fd_t, counters_fd: fd_t, comptime family: std.Io.net.IpAddress.Family) usize {
    const listener_key = if (family == .ip4) listener4_key else listener6_key;
    const error_counter: Counter = if (family == .ip4) .assign4_error else .assign6_error;
    _ = result.emit(BPF.Insn.st(.word, .r10, -20, listener_key));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, listeners_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(listeners_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -20));
    _ = result.emit(BPF.Insn.call(.map_lookup_elem));
    const listener_miss = result.emit(BPF.Insn.jeq(.r0, 0, 0));
    _ = result.emit(BPF.Insn.mov(.r7, .r0));
    _ = result.emit(BPF.Insn.mov(.r1, .r6));
    _ = result.emit(BPF.Insn.mov(.r2, .r7));
    _ = result.emit(BPF.Insn.mov(.r3, 0));
    _ = result.emit(BPF.Insn.call(.sk_assign));
    _ = result.emit(BPF.Insn.mov(.r8, .r0));
    _ = result.emit(BPF.Insn.mov(.r1, .r7));
    _ = result.emit(BPF.Insn.call(.sk_release));
    const assign_error = result.emit(BPF.Insn.jne(.r8, 0, 0));
    _ = result.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = result.emit(BPF.Insn.exit());
    const error_block = result.len;
    emitCounter(result, counters_fd, error_counter);
    const error_exit = result.emit(BPF.Insn.ja(0));
    result.patch(listener_miss, error_block);
    result.patch(assign_error, error_block);
    return error_exit;
}

fn program(fake4_fd: fd_t, fake6_fd: fd_t, listeners_fd: fd_t, counters_fd: fd_t, excluded4_fd: fd_t, excluded6_fd: fd_t, admissions_fd: fd_t, transparent_ifindex: ?u32, tail_programs_fd: ?fd_t) Program {
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
    const ipv6_fake_error_exit = emitFakeAssign(&result, listeners_fd, counters_fd, .ip6);

    const ipv6_literal = result.len;
    var ipv6_literal_exit_jumps: [2]usize = undefined;
    var ipv6_literal_exit_count: usize = 0;
    var ipv6_literal_assign_exits: ?AssignExits = null;
    if (transparent_ifindex) |ifindex| {
        _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "ingress_ifindex")));
        ipv6_literal_exit_jumps[ipv6_literal_exit_count] = result.emit(BPF.Insn.jne(.r2, @as(i32, @intCast(ifindex)), 0));
        ipv6_literal_exit_count += 1;
        _ = result.emit(BPF.Insn.st(.word, .r10, -20, 128));
        _ = result.emit(BPF.Insn.ld_map_fd1(.r1, excluded6_fd));
        _ = result.emit(BPF.Insn.ld_map_fd2(excluded6_fd));
        _ = result.emit(BPF.Insn.mov(.r2, .r10));
        _ = result.emit(BPF.Insn.add(.r2, -20));
        _ = result.emit(BPF.Insn.call(.map_lookup_elem));
        ipv6_literal_exit_jumps[ipv6_literal_exit_count] = result.emit(BPF.Insn.jne(.r0, 0, 0));
        ipv6_literal_exit_count += 1;
        emitCounter(&result, counters_fd, .lookup_miss);
        ipv6_literal_assign_exits = emitLiteralAssign(&result, listeners_fd, counters_fd, admissions_fd, .ip6);
    }

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
    const ipv4_fake_error_exit = emitFakeAssign(&result, listeners_fd, counters_fd, .ip4);

    const ipv4_literal = result.len;
    var ipv4_literal_exit_jumps: [2]usize = undefined;
    var ipv4_literal_exit_count: usize = 0;
    var ipv4_literal_assign_exits: ?AssignExits = null;
    if (transparent_ifindex) |ifindex| {
        _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "ingress_ifindex")));
        ipv4_literal_exit_jumps[ipv4_literal_exit_count] = result.emit(BPF.Insn.jne(.r2, @as(i32, @intCast(ifindex)), 0));
        ipv4_literal_exit_count += 1;
        _ = result.emit(BPF.Insn.st(.word, .r10, -8, 32));
        _ = result.emit(BPF.Insn.ld_map_fd1(.r1, excluded4_fd));
        _ = result.emit(BPF.Insn.ld_map_fd2(excluded4_fd));
        _ = result.emit(BPF.Insn.mov(.r2, .r10));
        _ = result.emit(BPF.Insn.add(.r2, -8));
        _ = result.emit(BPF.Insn.call(.map_lookup_elem));
        ipv4_literal_exit_jumps[ipv4_literal_exit_count] = result.emit(BPF.Insn.jne(.r0, 0, 0));
        ipv4_literal_exit_count += 1;
        emitCounter(&result, counters_fd, .lookup_miss);
        ipv4_literal_assign_exits = emitLiteralAssign(&result, listeners_fd, counters_fd, admissions_fd, .ip4);
    }

    var miss_exit_jump: ?usize = null;
    const lookup_miss = result.len;
    if (transparent_ifindex == null) {
        emitCounter(&result, counters_fd, .lookup_miss);
        if (tail_programs_fd) |programs_fd| {
            _ = result.emit(BPF.Insn.mov(.r1, .r6));
            _ = result.emit(BPF.Insn.ld_map_fd1(.r2, programs_fd));
            _ = result.emit(BPF.Insn.ld_map_fd2(programs_fd));
            _ = result.emit(BPF.Insn.mov(.r3, @as(i32, @intCast(literal_handler_index))));
            _ = result.emit(BPF.Insn.call(.tail_call));
        }
        miss_exit_jump = result.emit(BPF.Insn.ja(0));
    }
    const lookup_expiry = result.len;
    emitCounter(&result, counters_fd, .lookup_expiry);
    const exit_index = result.len;
    emitCounter(&result, counters_fd, .pass);
    _ = result.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = result.emit(BPF.Insn.exit());

    result.patch(non_tcp_jump, exit_index);
    result.patch(ipv4_jump, ipv4_start);
    result.patch(unknown_family_jump, exit_index);
    result.patch(ipv6_miss_jump, if (transparent_ifindex != null) ipv6_literal else lookup_miss);
    result.patch(ipv6_expiry_jump, lookup_expiry);
    result.patch(ipv4_miss_jump, if (transparent_ifindex != null) ipv4_literal else lookup_miss);
    result.patch(ipv4_expiry_jump, lookup_expiry);
    result.patch(ipv6_fake_error_exit, exit_index);
    result.patch(ipv4_fake_error_exit, exit_index);
    if (miss_exit_jump) |jump| result.patch(jump, exit_index);
    for (ipv6_literal_exit_jumps[0..ipv6_literal_exit_count]) |jump| result.patch(jump, exit_index);
    for (ipv4_literal_exit_jumps[0..ipv4_literal_exit_count]) |jump| result.patch(jump, exit_index);
    if (ipv6_literal_assign_exits) |exits| {
        result.patch(exits.success, exit_index);
        result.patch(exits.failure, exit_index);
    }
    if (ipv4_literal_assign_exits) |exits| {
        result.patch(exits.success, exit_index);
        result.patch(exits.failure, exit_index);
    }
    return result;
}

fn fakeProgram(fake4_fd: fd_t, fake6_fd: fd_t, listeners_fd: fd_t, counters_fd: fd_t, programs_fd: fd_t, enable_literal_tail: bool) Program {
    return program(fake4_fd, fake6_fd, listeners_fd, counters_fd, -1, -1, -1, null, if (enable_literal_tail) programs_fd else null);
}

fn dispatcherProgram(programs_fd: fd_t) Program {
    var result: Program = .{};
    _ = result.emit(BPF.Insn.mov(.r6, .r1));
    _ = result.emit(BPF.Insn.mov(.r1, .r6));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r2, programs_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(programs_fd));
    _ = result.emit(BPF.Insn.mov(.r3, @as(i32, @intCast(fake_handler_index))));
    _ = result.emit(BPF.Insn.call(.tail_call));
    _ = result.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = result.emit(BPF.Insn.exit());
    return result;
}

fn literalProgram(listeners_fd: fd_t, counters_fd: fd_t, excluded4_fd: fd_t, excluded6_fd: fd_t, admissions_fd: fd_t, transparent_ifindex: ?u32) Program {
    var result: Program = .{};
    _ = result.emit(BPF.Insn.mov(.r6, .r1));
    _ = result.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "protocol")));
    const non_tcp_jump = result.emit(BPF.Insn.jne(.r2, ipproto_tcp, 0));
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "ingress_ifindex")));
    const wrong_ingress_jump = result.emit(BPF.Insn.jne(.r2, @as(i32, @intCast(transparent_ifindex orelse 0)), 0));
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "family")));
    const ipv4_jump = result.emit(BPF.Insn.jeq(.r2, af_inet, 0));
    const unknown_family_jump = result.emit(BPF.Insn.jne(.r2, af_inet6, 0));

    inline for (0..4) |index| {
        _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip6") + index * 4));
        _ = result.emit(BPF.Insn.stx(.word, .r10, @intCast(-16 + @as(i32, @intCast(index * 4))), .r2));
    }
    _ = result.emit(BPF.Insn.st(.word, .r10, -20, 128));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, excluded6_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(excluded6_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -20));
    _ = result.emit(BPF.Insn.call(.map_lookup_elem));
    const excluded6_jump = result.emit(BPF.Insn.jne(.r0, 0, 0));
    emitCounter(&result, counters_fd, .lookup_miss);
    const assign6 = emitLiteralAssign(&result, listeners_fd, counters_fd, admissions_fd, .ip6);

    const ipv4_start = result.len;
    _ = result.emit(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip4")));
    _ = result.emit(BPF.Insn.stx(.word, .r10, -4, .r2));
    _ = result.emit(BPF.Insn.st(.word, .r10, -8, 32));
    _ = result.emit(BPF.Insn.ld_map_fd1(.r1, excluded4_fd));
    _ = result.emit(BPF.Insn.ld_map_fd2(excluded4_fd));
    _ = result.emit(BPF.Insn.mov(.r2, .r10));
    _ = result.emit(BPF.Insn.add(.r2, -8));
    _ = result.emit(BPF.Insn.call(.map_lookup_elem));
    const excluded4_jump = result.emit(BPF.Insn.jne(.r0, 0, 0));
    emitCounter(&result, counters_fd, .lookup_miss);
    const assign4 = emitLiteralAssign(&result, listeners_fd, counters_fd, admissions_fd, .ip4);

    const exit_index = result.len;
    emitCounter(&result, counters_fd, .pass);
    _ = result.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = result.emit(BPF.Insn.exit());
    result.patch(non_tcp_jump, exit_index);
    result.patch(wrong_ingress_jump, exit_index);
    result.patch(ipv4_jump, ipv4_start);
    result.patch(unknown_family_jump, exit_index);
    result.patch(excluded6_jump, exit_index);
    result.patch(excluded4_jump, exit_index);
    result.patch(assign6.success, exit_index);
    result.patch(assign6.failure, exit_index);
    result.patch(assign4.success, exit_index);
    result.patch(assign4.failure, exit_index);
    return result;
}

test "SK_LOOKUP program has stable UAPI-only instruction layout" {
    const generated = program(10, 11, 12, 13, 14, 15, 16, null, null);
    const instructions = generated.slice();
    var assign_count: usize = 0;
    var release_count: usize = 0;
    var counter_updates: usize = 0;
    var admission_updates: usize = 0;
    for (instructions) |instruction| {
        if (std.meta.eql(BPF.Insn.call(.sk_assign), instruction)) assign_count += 1;
        if (std.meta.eql(BPF.Insn.call(.sk_release), instruction)) release_count += 1;
        if (std.meta.eql(BPF.Insn.xadd(.r0, .r1), instruction)) counter_updates += 1;
        if (std.meta.eql(BPF.Insn.call(.map_update_elem), instruction)) admission_updates += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), assign_count);
    try std.testing.expectEqual(@as(usize, 2), release_count);
    try std.testing.expectEqual(@as(usize, 7), counter_updates);
    try std.testing.expectEqual(@as(usize, 0), admission_updates);
    try std.testing.expectEqual(BPF.Insn.exit(), instructions[instructions.len - 1]);
}

fn expectProgramReachable(instructions: []const BPF.Insn) !void {
    var reachable: [384]bool = @splat(false);
    if (instructions.len == 0 or instructions.len > reachable.len) return error.InvalidProgramLength;
    reachable[0] = true;
    var changed = true;
    while (changed) {
        changed = false;
        for (instructions, 0..) |instruction, index| {
            if (!reachable[index]) continue;
            if (instruction.code == 0x18) {
                if (index + 1 >= instructions.len) return error.TruncatedLdImm64;
                if (!reachable[index + 1]) {
                    reachable[index + 1] = true;
                    changed = true;
                }
                if (index + 2 < instructions.len and !reachable[index + 2]) {
                    reachable[index + 2] = true;
                    changed = true;
                }
                continue;
            }
            const class = instruction.code & 0x07;
            if (class == 0x05 or class == 0x06) {
                const operation = instruction.code & 0xf0;
                if (operation == 0x90) continue;
                if (operation != 0x80) {
                    const target_signed = @as(isize, @intCast(index)) + 1 + instruction.off;
                    if (target_signed < 0 or target_signed >= instructions.len) return error.JumpOutOfBounds;
                    const target: usize = @intCast(target_signed);
                    if (!reachable[target]) {
                        reachable[target] = true;
                        changed = true;
                    }
                    if (operation == 0x00) continue;
                }
            }
            if (index + 1 < instructions.len and !reachable[index + 1]) {
                reachable[index + 1] = true;
                changed = true;
            }
        }
    }
    for (reachable[0..instructions.len], 0..) |is_reachable, index| {
        if (!is_reachable) {
            std.debug.print("unreachable generated BPF instruction {d}\n", .{index});
            for (instructions[@max(index -| 3, 0)..@min(index + 4, instructions.len)], @max(index -| 3, 0)..) |instruction, instruction_index|
                std.debug.print("  {d}: code=0x{x} off={d} imm={d}\n", .{ instruction_index, instruction.code, instruction.off, instruction.imm });
            for (instructions, 0..) |instruction, source| {
                const class = instruction.code & 0x07;
                if ((class == 0x05 or class == 0x06) and (instruction.code & 0xf0) != 0x80 and @as(isize, @intCast(source)) + 1 + instruction.off == index)
                    std.debug.print("  incoming from {d}: code=0x{x} reachable={}\n", .{ source, instruction.code, reachable[source] });
            }
            return error.UnreachableInstruction;
        }
    }
}

test "generated SK_LOOKUP programs have no unreachable instructions" {
    try expectProgramReachable(program(10, 11, 12, 13, 14, 15, 16, null, null).slice());
    try expectProgramReachable(program(10, 11, 12, 13, 14, 15, 16, 7, null).slice());
    try expectProgramReachable(dispatcherProgram(17).slice());
    try expectProgramReachable(fakeProgram(10, 11, 12, 13, 17, true).slice());
    try expectProgramReachable(literalProgram(12, 13, 14, 15, 16, 7).slice());
}

test "tail-call dispatcher and handlers remain isolated" {
    const dispatcher = dispatcherProgram(17);
    const fake = fakeProgram(10, 11, 12, 13, 17, true);
    const literal = literalProgram(12, 13, 14, 15, 16, 7);
    var dispatcher_tails: usize = 0;
    var fake_tails: usize = 0;
    var literal_tails: usize = 0;
    var fake_assigns: usize = 0;
    var literal_assigns: usize = 0;
    var literal_admissions: usize = 0;
    for (dispatcher.slice()) |instruction| {
        if (std.meta.eql(BPF.Insn.call(.tail_call), instruction)) dispatcher_tails += 1;
    }
    for (fake.slice()) |instruction| {
        if (std.meta.eql(BPF.Insn.call(.tail_call), instruction)) fake_tails += 1;
        if (std.meta.eql(BPF.Insn.call(.sk_assign), instruction)) fake_assigns += 1;
        try std.testing.expect(!std.meta.eql(BPF.Insn.call(.map_update_elem), instruction));
    }
    for (literal.slice()) |instruction| {
        if (std.meta.eql(BPF.Insn.call(.tail_call), instruction)) literal_tails += 1;
        if (std.meta.eql(BPF.Insn.call(.sk_assign), instruction)) literal_assigns += 1;
        if (std.meta.eql(BPF.Insn.call(.map_update_elem), instruction)) literal_admissions += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), dispatcher_tails);
    try std.testing.expectEqual(@as(usize, 1), fake_tails);
    try std.testing.expectEqual(@as(usize, 0), literal_tails);
    try std.testing.expectEqual(@as(usize, 2), fake_assigns);
    try std.testing.expectEqual(@as(usize, 2), literal_assigns);
    try std.testing.expectEqual(@as(usize, 2), literal_admissions);
}

test "tail-call FakeDNS hit suffix matches standalone control" {
    const control = fakeProgram(10, 11, 12, 13, 17, false);
    const handler = fakeProgram(10, 11, 12, 13, 17, true);
    var control_assigns: [2]usize = undefined;
    var handler_assigns: [2]usize = undefined;
    var control_count: usize = 0;
    var handler_count: usize = 0;
    for (control.slice(), 0..) |instruction, index| {
        if (std.meta.eql(BPF.Insn.call(.sk_assign), instruction)) {
            control_assigns[control_count] = index;
            control_count += 1;
        }
    }
    for (handler.slice(), 0..) |instruction, index| {
        if (std.meta.eql(BPF.Insn.call(.sk_assign), instruction)) {
            handler_assigns[handler_count] = index;
            handler_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), control_count);
    try std.testing.expectEqual(@as(usize, 2), handler_count);
    for (control_assigns, handler_assigns) |control_index, handler_index| {
        try std.testing.expectEqualSlices(
            BPF.Insn,
            control.slice()[control_index - 3 .. control_index + 7],
            handler.slice()[handler_index - 3 .. handler_index + 7],
        );
    }
}

test "combined SK_LOOKUP program gives FakeDNS a compact terminal assignment path" {
    const generated = program(10, 11, 12, 13, 14, 15, 16, 7, null);
    var assign_count: usize = 0;
    var ingress_loads: usize = 0;
    var admission_updates: usize = 0;
    var fake_map_loads: usize = 0;
    var assigns: [4]usize = undefined;
    for (generated.slice(), 0..) |instruction, index| {
        if (std.meta.eql(BPF.Insn.call(.sk_assign), instruction)) {
            assigns[assign_count] = index;
            assign_count += 1;
        }
        if (std.meta.eql(BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "ingress_ifindex")), instruction)) ingress_loads += 1;
        if (std.meta.eql(BPF.Insn.call(.map_update_elem), instruction)) admission_updates += 1;
        if (std.meta.eql(BPF.Insn.ld_map_fd1(.r1, 10), instruction) or std.meta.eql(BPF.Insn.ld_map_fd1(.r1, 11), instruction)) fake_map_loads += 1;
        try std.testing.expect(instruction.dst != @intFromEnum(BPF.Insn.Reg.r9));
    }
    try std.testing.expectEqual(@as(usize, 4), assign_count);
    try std.testing.expectEqual(@as(usize, 2), ingress_loads);
    try std.testing.expectEqual(@as(usize, 2), admission_updates);
    try std.testing.expectEqual(@as(usize, 2), fake_map_loads);
    for ([_]usize{ assigns[0], assigns[2] }) |index| {
        try std.testing.expectEqual(BPF.Insn.mov(.r8, .r0), generated.slice()[index + 1]);
        try std.testing.expectEqual(BPF.Insn.mov(.r1, .r7), generated.slice()[index + 2]);
        try std.testing.expectEqual(BPF.Insn.call(.sk_release), generated.slice()[index + 3]);
        try std.testing.expectEqual(BPF.Insn.mov(.r0, sk_pass), generated.slice()[index + 5]);
        try std.testing.expectEqual(BPF.Insn.exit(), generated.slice()[index + 6]);
    }
    try std.testing.expectEqual(BPF.Insn.exit(), generated.slice()[generated.slice().len - 1]);
}

test "FakeDNS-only and combined programs use identical assign and release ABI" {
    const control = program(10, 11, 12, 13, 14, 15, 16, null, null);
    const combined = program(10, 11, 12, 13, 14, 15, 16, 7, null);
    var control_assigns: [2]usize = undefined;
    var combined_assigns: [4]usize = undefined;
    var control_count: usize = 0;
    var combined_count: usize = 0;
    for (control.slice(), 0..) |instruction, index| if (std.meta.eql(BPF.Insn.call(.sk_assign), instruction)) {
        control_assigns[control_count] = index;
        control_count += 1;
    };
    for (combined.slice(), 0..) |instruction, index| if (std.meta.eql(BPF.Insn.call(.sk_assign), instruction)) {
        combined_assigns[combined_count] = index;
        combined_count += 1;
    };
    try std.testing.expectEqual(@as(usize, 2), control_count);
    try std.testing.expectEqual(@as(usize, 4), combined_count);
    for (control_assigns, [_]usize{ combined_assigns[0], combined_assigns[2] }) |control_index, combined_index| {
        try std.testing.expectEqualSlices(
            BPF.Insn,
            control.slice()[control_index - 3 .. control_index + 7],
            combined.slice()[combined_index - 3 .. combined_index + 7],
        );
        try std.testing.expectEqual(BPF.Insn.mov(.r3, 0), combined.slice()[combined_index - 1]);
        try std.testing.expectEqual(BPF.Insn.call(.sk_release), combined.slice()[combined_index + 3]);
    }
}

test "literal admission proof binds both endpoints and ports" {
    const local = try std.Io.net.IpAddress.parse("203.0.113.7", 443);
    const peer1 = try std.Io.net.IpAddress.parse("192.0.2.10", 50000);
    const peer2 = try std.Io.net.IpAddress.parse("192.0.2.10", 50001);
    const key1 = admissionKey(local, peer1).?;
    const key2 = admissionKey(local, peer2).?;
    try std.testing.expectEqual(@as(u32, af_inet), key1.family);
    try std.testing.expectEqual(@as(u32, 443), key1.local_port);
    try std.testing.expectEqual(std.mem.nativeToBig(u16, 50000), key1.remote_port);
    try std.testing.expect(!std.meta.eql(key1, key2));
    try std.testing.expect(admissionKey(local, try std.Io.net.IpAddress.parse("2001:db8::1", 50000)) == null);
}

test "literal admission proof expires and rejects future timestamps" {
    try std.testing.expect(admissionFresh(100, 101));
    try std.testing.expect(!admissionFresh(0, 101));
    try std.testing.expect(!admissionFresh(200, 101));
    try std.testing.expect(!admissionFresh(100, 100 + admission_validity_ns + 1));
}

test "FakeDNS pools and operator exclusions produce LPM keys" {
    var key4: [8]u8 = @splat(0);
    std.mem.writeInt(u32, key4[0..4], 15, .native);
    @memcpy(key4[4..8], &[_]u8{ 198, 18, 0, 0 });
    try std.testing.expectEqual(@as(u32, 15), std.mem.readInt(u32, key4[0..4], .native));
    try std.testing.expectEqualSlices(u8, &.{ 198, 18, 0, 0 }, key4[4..8]);
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
