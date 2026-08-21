const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../config/mod.zig");

pub const Error = error{
    InvalidFakeDnsPool,
    FakeDnsPoolExhausted,
    DomainTooLong,
    InvalidFakeDnsPersistentState,
};

pub const Publication = extern struct {
    domain_id: u64,
    generation: u64,
    route_valid_until_ns: u64,
};

pub const LeasePublication = struct {
    dataplane: Publication,
    domain: []const u8,
    dns_expires_ns: u64,
};

pub const RestoredLease = struct {
    family: net.IpAddress.Family,
    address: [16]u8,
    publication: Publication,
    dns_expires_ns: u64,
    domain: []const u8,
};

pub const RestoreVisitor = *const fn (?*anyopaque, RestoredLease) anyerror!void;

/// Called under the Store mutex. Implementations must not call back into Store.
/// Publication completes before the synthetic address is returned to DNS.
pub const Publisher = struct {
    context: ?*anyopaque = null,
    publish4_fn: ?*const fn (?*anyopaque, [4]u8, LeasePublication) anyerror!void = null,
    publish6_fn: ?*const fn (?*anyopaque, [16]u8, LeasePublication) anyerror!void = null,
    remove4_fn: ?*const fn (?*anyopaque, [4]u8) void = null,
    remove6_fn: ?*const fn (?*anyopaque, [16]u8) void = null,
    restore_fn: ?*const fn (?*anyopaque, u64, ?*anyopaque, RestoreVisitor) anyerror!void = null,

    pub fn publish4(self: Publisher, address: [4]u8, value: LeasePublication) !void {
        if (self.publish4_fn) |publish| try publish(self.context, address, value);
    }
    pub fn publish6(self: Publisher, address: [16]u8, value: LeasePublication) !void {
        if (self.publish6_fn) |publish| try publish(self.context, address, value);
    }
    fn remove4(self: Publisher, address: [4]u8) void {
        if (self.remove4_fn) |remove| remove(self.context, address);
    }
    fn remove6(self: Publisher, address: [16]u8) void {
        if (self.remove6_fn) |remove| remove(self.context, address);
    }
    fn restore(self: Publisher, now_ns: u64, visitor_context: ?*anyopaque, visitor: RestoreVisitor) !void {
        if (self.restore_fn) |restore_fn| try restore_fn(self.context, now_ns, visitor_context, visitor);
    }
};

pub const DomainRecord = struct {
    id: u64,
    name: []const u8,
    lease4: ?*Lease4 = null,
    lease6: ?*Lease6 = null,
    active_refs: u32 = 0,
};

pub const Lease4 = struct {
    record: *DomainRecord,
    address: [4]u8,
    generation: u64,
    dns_expires_ns: u64,
    reuse_after_ns: u64,
    active_refs: u32 = 0,
};

pub const Lease6 = struct {
    record: *DomainRecord,
    address: [16]u8,
    generation: u64,
    dns_expires_ns: u64,
    reuse_after_ns: u64,
    active_refs: u32 = 0,
};

pub const LeaseHandle = struct {
    store: *Store,
    record: *DomainRecord,
    family: net.IpAddress.Family,
    generation: u64,
    released: bool = false,

    pub fn domain(self: *const LeaseHandle) []const u8 {
        return self.record.name;
    }
    pub fn domainId(self: *const LeaseHandle) u64 {
        return self.record.id;
    }
    pub fn release(self: *LeaseHandle, io: Io) void {
        if (self.released) return;
        self.store.mutex.lockUncancelable(io);
        defer self.store.mutex.unlock(io);
        const refs = switch (self.family) {
            .ip4 => &self.record.lease4.?.active_refs,
            .ip6 => &self.record.lease6.?.active_refs,
        };
        std.debug.assert(refs.* > 0 and self.record.active_refs > 0);
        refs.* -= 1;
        self.record.active_refs -= 1;
        self.released = true;
    }
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    publisher: Publisher,
    ttl_ns: u64,
    reuse_grace_ns: u64,
    pool_base: u32,
    prefix_len: u8,
    usable_count: u32,
    next_offset: u32,
    pool6_base: [16]u8,
    pool6_prefix_len: u8,
    pool6_usable_count: u64,
    pool6_next_offset: u64,
    next_domain_id: u64 = 1,
    mutex: Io.Mutex = .init,
    domains: std.StringHashMap(*DomainRecord),
    domain_ids: std.AutoHashMap(u64, *DomainRecord),
    leases4: std.AutoHashMap(u32, *Lease4),
    leases6: std.AutoHashMap([16]u8, *Lease6),
    generations4: std.AutoHashMap(u32, u64),
    generations6: std.AutoHashMap([16]u8, u64),

    pub fn init(allocator: std.mem.Allocator, cfg: config.FakeDnsConfig) !Store {
        return initWithPublisher(allocator, cfg, .{});
    }

    pub fn initWithPublisher(allocator: std.mem.Allocator, cfg: config.FakeDnsConfig, publisher: Publisher) !Store {
        return initRestored(allocator, cfg, publisher, 0);
    }

    pub fn initRestored(
        allocator: std.mem.Allocator,
        cfg: config.FakeDnsConfig,
        publisher: Publisher,
        now_ns: u64,
    ) !Store {
        const pool = try parsePool(cfg.ip_pool);
        const pool6 = try parsePool6(cfg.ip_pool6);
        var store: Store = .{
            .allocator = allocator,
            .publisher = publisher,
            .ttl_ns = secondsToNs(cfg.ttl),
            .reuse_grace_ns = secondsToNs(cfg.reuse_grace_seconds),
            .pool_base = pool.base,
            .prefix_len = pool.prefix_len,
            .usable_count = pool.usable_count,
            .next_offset = 1,
            .pool6_base = pool6.base,
            .pool6_prefix_len = pool6.prefix_len,
            .pool6_usable_count = pool6.usable_count,
            .pool6_next_offset = 0,
            .domains = std.StringHashMap(*DomainRecord).init(allocator),
            .domain_ids = std.AutoHashMap(u64, *DomainRecord).init(allocator),
            .leases4 = std.AutoHashMap(u32, *Lease4).init(allocator),
            .leases6 = std.AutoHashMap([16]u8, *Lease6).init(allocator),
            .generations4 = std.AutoHashMap(u32, u64).init(allocator),
            .generations6 = std.AutoHashMap([16]u8, u64).init(allocator),
        };
        errdefer store.deinit();
        var restore_context: RestoreContext = .{ .store = &store, .now_ns = now_ns };
        try publisher.restore(now_ns, &restore_context, restoreLease);
        return store;
    }

    pub fn deinit(self: *Store) void {
        var it4 = self.leases4.valueIterator();
        while (it4.next()) |ptr| {
            std.debug.assert(ptr.*.active_refs == 0);
            self.allocator.destroy(ptr.*);
        }
        var it6 = self.leases6.valueIterator();
        while (it6.next()) |ptr| {
            std.debug.assert(ptr.*.active_refs == 0);
            self.allocator.destroy(ptr.*);
        }
        var domains = self.domains.valueIterator();
        while (domains.next()) |ptr| {
            std.debug.assert(ptr.*.active_refs == 0);
            self.allocator.free(ptr.*.name);
            self.allocator.destroy(ptr.*);
        }
        self.domains.deinit();
        self.domain_ids.deinit();
        self.leases4.deinit();
        self.leases6.deinit();
        self.generations4.deinit();
        self.generations6.deinit();
        self.* = undefined;
    }

    pub fn resolveA(self: *Store, domain: []const u8, io: Io) ![4]u8 {
        return self.resolveAAt(domain, monotonicNowNs(io), io);
    }
    pub fn resolveAAAA(self: *Store, domain: []const u8, io: Io) ![16]u8 {
        return self.resolveAAAAAt(domain, monotonicNowNs(io), io);
    }

    pub fn resolveAAt(self: *Store, domain: []const u8, now_ns: u64, io: Io) ![4]u8 {
        var buffer: [net.HostName.max_len]u8 = undefined;
        const normalized = try normalizeDomain(&buffer, domain);
        try self.mutex.lock(io);
        defer self.mutex.unlock(io);
        if (self.domains.get(normalized)) |record| if (record.lease4) |lease| {
            const deadlines = self.expiration(now_ns);
            try self.publisher.publish4(lease.address, leasePublication(record, lease.generation, deadlines.dns, deadlines.reuse_after));
            lease.dns_expires_ns = deadlines.dns;
            lease.reuse_after_ns = deadlines.reuse_after;
            return lease.address;
        };
        return self.allocate4(normalized, now_ns);
    }

    pub fn resolveAAAAAt(self: *Store, domain: []const u8, now_ns: u64, io: Io) ![16]u8 {
        var buffer: [net.HostName.max_len]u8 = undefined;
        const normalized = try normalizeDomain(&buffer, domain);
        try self.mutex.lock(io);
        defer self.mutex.unlock(io);
        if (self.domains.get(normalized)) |record| if (record.lease6) |lease| {
            const deadlines = self.expiration(now_ns);
            try self.publisher.publish6(lease.address, leasePublication(record, lease.generation, deadlines.dns, deadlines.reuse_after));
            lease.dns_expires_ns = deadlines.dns;
            lease.reuse_after_ns = deadlines.reuse_after;
            return lease.address;
        };
        return self.allocate6(normalized, now_ns);
    }

    pub fn lookup(self: *Store, address: net.IpAddress, io: Io) ?LeaseHandle {
        return self.lookupAt(address, monotonicNowNs(io), io);
    }

    pub fn lookupAt(self: *Store, address: net.IpAddress, now_ns: u64, io: Io) ?LeaseHandle {
        self.mutex.lock(io) catch return null;
        defer self.mutex.unlock(io);
        return switch (address) {
            .ip4 => |ip| if (self.leases4.get(bytesToIp(ip.bytes))) |lease| self.acquire4(lease, now_ns) else null,
            .ip6 => |ip| if (self.leases6.get(ip.bytes)) |lease| self.acquire6(lease, now_ns) else null,
        };
    }

    pub fn contains(self: *const Store, address: net.IpAddress) bool {
        return switch (address) {
            .ip4 => |ip| (bytesToIp(ip.bytes) & prefixMask(self.prefix_len)) == self.pool_base,
            .ip6 => |ip| prefixMatches6(ip.bytes, self.pool6_base, self.pool6_prefix_len),
        };
    }

    fn allocate4(self: *Store, normalized: []const u8, now_ns: u64) ![4]u8 {
        const candidate = self.findCandidate4(now_ns) orelse return error.FakeDnsPoolExhausted;
        const generation = incrementGeneration(self.generations4.get(candidate.ip) orelse 0);
        const deadlines = self.expiration(now_ns);
        var pending = try self.getOrCreateRecord(normalized);
        defer pending.rollback(self);
        if (candidate.lease == null) try self.leases4.ensureUnusedCapacity(1);
        if (!self.generations4.contains(candidate.ip)) try self.generations4.ensureUnusedCapacity(1);
        const created_lease = if (candidate.lease == null) try self.allocator.create(Lease4) else null;
        errdefer if (created_lease) |lease| self.allocator.destroy(lease);
        const address = ipToBytes(candidate.ip);
        try self.publisher.publish4(address, leasePublication(pending.record, generation, deadlines.dns, deadlines.reuse_after));

        const old_record = if (candidate.lease) |old| old.record else null;
        const lease = candidate.lease orelse created_lease.?;
        if (old_record) |record| record.lease4 = null;
        lease.* = .{
            .record = pending.record,
            .address = address,
            .generation = generation,
            .dns_expires_ns = deadlines.dns,
            .reuse_after_ns = deadlines.reuse_after,
        };
        if (candidate.lease == null) self.leases4.putAssumeCapacity(candidate.ip, lease);
        self.generations4.putAssumeCapacity(candidate.ip, generation);
        pending.record.lease4 = lease;
        pending.commit(self);
        if (old_record) |record| self.destroyUnusedRecord(record);
        self.advance4();
        return address;
    }

    fn allocate6(self: *Store, normalized: []const u8, now_ns: u64) ![16]u8 {
        const candidate = self.findCandidate6(now_ns) orelse return error.FakeDnsPoolExhausted;
        const generation = incrementGeneration(self.generations6.get(candidate.ip) orelse 0);
        const deadlines = self.expiration(now_ns);
        var pending = try self.getOrCreateRecord(normalized);
        defer pending.rollback(self);
        if (candidate.lease == null) try self.leases6.ensureUnusedCapacity(1);
        if (!self.generations6.contains(candidate.ip)) try self.generations6.ensureUnusedCapacity(1);
        const created_lease = if (candidate.lease == null) try self.allocator.create(Lease6) else null;
        errdefer if (created_lease) |lease| self.allocator.destroy(lease);
        try self.publisher.publish6(candidate.ip, leasePublication(pending.record, generation, deadlines.dns, deadlines.reuse_after));

        const old_record = if (candidate.lease) |old| old.record else null;
        const lease = candidate.lease orelse created_lease.?;
        if (old_record) |record| record.lease6 = null;
        lease.* = .{
            .record = pending.record,
            .address = candidate.ip,
            .generation = generation,
            .dns_expires_ns = deadlines.dns,
            .reuse_after_ns = deadlines.reuse_after,
        };
        if (candidate.lease == null) self.leases6.putAssumeCapacity(candidate.ip, lease);
        self.generations6.putAssumeCapacity(candidate.ip, generation);
        pending.record.lease6 = lease;
        pending.commit(self);
        if (old_record) |record| self.destroyUnusedRecord(record);
        self.advance6();
        return candidate.ip;
    }

    const PendingRecord = struct {
        record: *DomainRecord,
        created: bool,
        committed: bool = false,
        fn commit(self: *PendingRecord, store: *Store) void {
            if (self.created) {
                store.domains.putAssumeCapacity(self.record.name, self.record);
                store.domain_ids.putAssumeCapacity(self.record.id, self.record);
            }
            self.committed = true;
        }
        fn rollback(self: *PendingRecord, store: *Store) void {
            if (!self.created or self.committed) return;
            store.allocator.free(self.record.name);
            store.allocator.destroy(self.record);
        }
    };

    fn getOrCreateRecord(self: *Store, normalized: []const u8) !PendingRecord {
        if (self.domains.get(normalized)) |record| return .{ .record = record, .created = false };
        try self.domains.ensureUnusedCapacity(1);
        try self.domain_ids.ensureUnusedCapacity(1);
        const owned = try self.allocator.dupe(u8, normalized);
        errdefer self.allocator.free(owned);
        const record = try self.allocator.create(DomainRecord);
        record.* = .{ .id = self.next_domain_id, .name = owned };
        self.next_domain_id = incrementGeneration(self.next_domain_id);
        return .{ .record = record, .created = true };
    }

    fn destroyUnusedRecord(self: *Store, record: *DomainRecord) void {
        if (record.lease4 != null or record.lease6 != null or record.active_refs != 0) return;
        std.debug.assert(self.domains.remove(record.name));
        std.debug.assert(self.domain_ids.remove(record.id));
        self.allocator.free(record.name);
        self.allocator.destroy(record);
    }

    fn acquire4(self: *Store, lease: *Lease4, now_ns: u64) ?LeaseHandle {
        if (now_ns >= lease.reuse_after_ns) return null;
        lease.active_refs += 1;
        lease.record.active_refs += 1;
        return .{ .store = self, .record = lease.record, .family = .ip4, .generation = lease.generation };
    }
    fn acquire6(self: *Store, lease: *Lease6, now_ns: u64) ?LeaseHandle {
        if (now_ns >= lease.reuse_after_ns) return null;
        lease.active_refs += 1;
        lease.record.active_refs += 1;
        return .{ .store = self, .record = lease.record, .family = .ip6, .generation = lease.generation };
    }

    const Candidate4 = struct { ip: u32, lease: ?*Lease4 };
    const Candidate6 = struct { ip: [16]u8, lease: ?*Lease6 };

    fn findCandidate4(self: *Store, now_ns: u64) ?Candidate4 {
        const limit: u64 = @min(@as(u64, self.usable_count), @as(u64, self.leases4.count()) + 1);
        var offset = self.next_offset;
        var scanned: u64 = 0;
        while (scanned < limit) : (scanned += 1) {
            const ip = self.pool_base + offset;
            const lease = self.leases4.get(ip);
            if (lease == null or (lease.?.active_refs == 0 and now_ns >= lease.?.reuse_after_ns)) return .{ .ip = ip, .lease = lease };
            offset += 1;
            if (offset > self.usable_count) offset = 1;
        }
        return null;
    }
    fn findCandidate6(self: *Store, now_ns: u64) ?Candidate6 {
        const limit: u64 = @min(self.pool6_usable_count, @as(u64, self.leases6.count()) + 1);
        var offset = self.pool6_next_offset;
        var scanned: u64 = 0;
        while (scanned < limit) : (scanned += 1) {
            const ip = addOffset6(self.pool6_base, offset);
            const lease = self.leases6.get(ip);
            if (lease == null or (lease.?.active_refs == 0 and now_ns >= lease.?.reuse_after_ns)) return .{ .ip = ip, .lease = lease };
            offset += 1;
            if (offset >= self.pool6_usable_count) offset = 0;
        }
        return null;
    }

    fn advance4(self: *Store) void {
        self.next_offset += 1;
        if (self.next_offset > self.usable_count) self.next_offset = 1;
    }
    fn advance6(self: *Store) void {
        self.pool6_next_offset += 1;
        if (self.pool6_next_offset >= self.pool6_usable_count) self.pool6_next_offset = 0;
    }
    fn expiration(self: *const Store, now_ns: u64) struct { dns: u64, reuse_after: u64 } {
        const dns = saturatingAdd(now_ns, self.ttl_ns);
        return .{ .dns = dns, .reuse_after = saturatingAdd(dns, self.reuse_grace_ns) };
    }

    fn restoreOne(self: *Store, restored: RestoredLease, now_ns: u64) !void {
        if (now_ns >= restored.publication.route_valid_until_ns) return;
        if (restored.publication.domain_id == 0 or
            restored.publication.domain_id == std.math.maxInt(u64) or
            restored.publication.generation == 0 or
            restored.dns_expires_ns > restored.publication.route_valid_until_ns)
        {
            return error.InvalidFakeDnsPersistentState;
        }
        var normalized_buffer: [net.HostName.max_len]u8 = undefined;
        const normalized = try normalizeDomain(&normalized_buffer, restored.domain);
        if (!std.mem.eql(u8, normalized, restored.domain)) return error.InvalidFakeDnsPersistentState;

        const address4: ?u32 = switch (restored.family) {
            .ip4 => blk: {
                const ip = bytesToIp(restored.address[0..4].*);
                if ((ip & prefixMask(self.prefix_len)) != self.pool_base or
                    ip == self.pool_base or ip - self.pool_base > self.usable_count)
                {
                    return error.InvalidFakeDnsPersistentState;
                }
                if (self.leases4.contains(ip)) return error.InvalidFakeDnsPersistentState;
                break :blk ip;
            },
            .ip6 => blk: {
                if (!prefixMatches6(restored.address, self.pool6_base, self.pool6_prefix_len) or
                    self.leases6.contains(restored.address))
                {
                    return error.InvalidFakeDnsPersistentState;
                }
                break :blk null;
            },
        };

        var created_record = false;
        const record = if (self.domain_ids.get(restored.publication.domain_id)) |existing| blk: {
            if (!std.mem.eql(u8, existing.name, restored.domain)) return error.InvalidFakeDnsPersistentState;
            break :blk existing;
        } else if (self.domains.get(restored.domain)) |_| {
            return error.InvalidFakeDnsPersistentState;
        } else blk: {
            try self.domains.ensureUnusedCapacity(1);
            try self.domain_ids.ensureUnusedCapacity(1);
            const owned_name = try self.allocator.dupe(u8, restored.domain);
            errdefer self.allocator.free(owned_name);
            const created = try self.allocator.create(DomainRecord);
            created.* = .{ .id = restored.publication.domain_id, .name = owned_name };
            self.domains.putAssumeCapacity(created.name, created);
            self.domain_ids.putAssumeCapacity(created.id, created);
            created_record = true;
            break :blk created;
        };
        var committed = false;
        errdefer if (created_record and !committed) {
            std.debug.assert(self.domains.remove(record.name));
            std.debug.assert(self.domain_ids.remove(record.id));
            self.allocator.free(record.name);
            self.allocator.destroy(record);
        };

        switch (restored.family) {
            .ip4 => {
                if (record.lease4 != null) return error.InvalidFakeDnsPersistentState;
                try self.leases4.ensureUnusedCapacity(1);
                if (!self.generations4.contains(address4.?)) try self.generations4.ensureUnusedCapacity(1);
                const lease = try self.allocator.create(Lease4);
                lease.* = .{
                    .record = record,
                    .address = restored.address[0..4].*,
                    .generation = restored.publication.generation,
                    .dns_expires_ns = restored.dns_expires_ns,
                    .reuse_after_ns = restored.publication.route_valid_until_ns,
                };
                self.leases4.putAssumeCapacity(address4.?, lease);
                self.generations4.putAssumeCapacity(address4.?, restored.publication.generation);
                record.lease4 = lease;
                const offset = address4.? - self.pool_base;
                self.next_offset = if (offset == self.usable_count) 1 else offset + 1;
            },
            .ip6 => {
                if (record.lease6 != null) return error.InvalidFakeDnsPersistentState;
                try self.leases6.ensureUnusedCapacity(1);
                if (!self.generations6.contains(restored.address)) try self.generations6.ensureUnusedCapacity(1);
                const lease = try self.allocator.create(Lease6);
                lease.* = .{
                    .record = record,
                    .address = restored.address,
                    .generation = restored.publication.generation,
                    .dns_expires_ns = restored.dns_expires_ns,
                    .reuse_after_ns = restored.publication.route_valid_until_ns,
                };
                self.leases6.putAssumeCapacity(restored.address, lease);
                self.generations6.putAssumeCapacity(restored.address, restored.publication.generation);
                record.lease6 = lease;
            },
        }
        self.next_domain_id = @max(self.next_domain_id, restored.publication.domain_id + 1);
        committed = true;
    }
};

const RestoreContext = struct {
    store: *Store,
    now_ns: u64,
};

fn restoreLease(context: ?*anyopaque, restored: RestoredLease) !void {
    const restore_context: *RestoreContext = @ptrCast(@alignCast(context.?));
    try restore_context.store.restoreOne(restored, restore_context.now_ns);
}

fn leasePublication(
    record: *const DomainRecord,
    generation: u64,
    dns_expires_ns: u64,
    reuse_after_ns: u64,
) LeasePublication {
    return .{
        .dataplane = .{
            .domain_id = record.id,
            .generation = generation,
            .route_valid_until_ns = reuse_after_ns,
        },
        .domain = record.name,
        .dns_expires_ns = dns_expires_ns,
    };
}

/// bpf_ktime_get_ns and Io `.awake` both use CLOCK_MONOTONIC on Linux.
pub fn monotonicNowNs(io: Io) u64 {
    return @intCast(@max(Io.Timestamp.now(io, .awake).nanoseconds, 0));
}
fn secondsToNs(seconds: u32) u64 {
    return @as(u64, seconds) * std.time.ns_per_s;
}
fn saturatingAdd(a: u64, b: u64) u64 {
    return std.math.add(u64, a, b) catch std.math.maxInt(u64);
}
fn incrementGeneration(value: u64) u64 {
    return std.math.add(u64, value, 1) catch std.math.maxInt(u64);
}

fn parsePool(text: []const u8) !struct { base: u32, prefix_len: u8, usable_count: u32 } {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidFakeDnsPool;
    const prefix_len = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return error.InvalidFakeDnsPool;
    if (prefix_len > 30) return error.InvalidFakeDnsPool;
    const parsed = net.IpAddress.parse(text[0..slash], 0) catch return error.InvalidFakeDnsPool;
    const address = switch (parsed) {
        .ip4 => |ip| bytesToIp(ip.bytes),
        .ip6 => return error.InvalidFakeDnsPool,
    };
    const total: u64 = @as(u64, 1) << @intCast(32 - prefix_len);
    return .{ .base = address & prefixMask(prefix_len), .prefix_len = prefix_len, .usable_count = @intCast(total - 2) };
}
fn prefixMask(prefix_len: u8) u32 {
    if (prefix_len == 0) return 0;
    return std.math.shl(u32, std.math.maxInt(u32), 32 - prefix_len);
}
fn parsePool6(text: []const u8) !struct { base: [16]u8, prefix_len: u8, usable_count: u64 } {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidFakeDnsPool;
    const prefix_len = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return error.InvalidFakeDnsPool;
    if (prefix_len > 128) return error.InvalidFakeDnsPool;
    const parsed = net.IpAddress.parse(text[0..slash], 0) catch return error.InvalidFakeDnsPool;
    var base = switch (parsed) {
        .ip4 => return error.InvalidFakeDnsPool,
        .ip6 => |ip| ip.bytes,
    };
    maskNetwork6(&base, prefix_len);
    const host_bits: u8 = 128 - prefix_len;
    return .{ .base = base, .prefix_len = prefix_len, .usable_count = if (host_bits >= 64) std.math.maxInt(u64) else @as(u64, 1) << @intCast(host_bits) };
}
fn maskNetwork6(address: *[16]u8, prefix_len: u8) void {
    const full = prefix_len / 8;
    const remaining = prefix_len % 8;
    var index: usize = full;
    if (remaining != 0) {
        const shift: u3 = @intCast(8 - remaining);
        address[index] &= @as(u8, 0xff) << shift;
        index += 1;
    }
    @memset(address[index..], 0);
}
fn prefixMatches6(address: [16]u8, network: [16]u8, prefix_len: u8) bool {
    const full = prefix_len / 8;
    if (!std.mem.eql(u8, address[0..full], network[0..full])) return false;
    const remaining = prefix_len % 8;
    if (remaining == 0) return true;
    const shift: u3 = @intCast(8 - remaining);
    const mask = @as(u8, 0xff) << shift;
    return (address[full] & mask) == (network[full] & mask);
}
fn addOffset6(base: [16]u8, offset: u64) [16]u8 {
    var address = base;
    var carry = offset;
    var index: usize = address.len;
    while (index > 0 and carry != 0) {
        index -= 1;
        const sum: u16 = @as(u16, address[index]) + @as(u16, @truncate(carry));
        address[index] = @truncate(sum);
        carry = (carry >> 8) + (sum >> 8);
    }
    return address;
}
fn normalizeDomain(buffer: *[net.HostName.max_len]u8, domain: []const u8) ![]const u8 {
    var trimmed = domain;
    while (trimmed.len > 0 and trimmed[trimmed.len - 1] == '.') trimmed = trimmed[0 .. trimmed.len - 1];
    if (trimmed.len == 0 or trimmed.len > net.HostName.max_len) return error.DomainTooLong;
    for (trimmed, 0..) |c, i| buffer[i] = std.ascii.toLower(c);
    return buffer[0..trimmed.len];
}
fn bytesToIp(bytes: [4]u8) u32 {
    return std.mem.readInt(u32, &bytes, .big);
}
fn ipToBytes(ip: u32) [4]u8 {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, ip, .big);
    return bytes;
}

const test_config: config.FakeDnsConfig = .{ .ip_pool = "198.18.0.0/30", .ip_pool6 = "fc00::/126", .ttl = 10, .reuse_grace_seconds = 5 };

const TestRestoreSource = struct {
    leases: []const RestoredLease,
    fail_after: ?usize = null,

    fn restore(
        context: ?*anyopaque,
        now_ns: u64,
        visitor_context: ?*anyopaque,
        visitor: RestoreVisitor,
    ) !void {
        _ = now_ns;
        const self: *TestRestoreSource = @ptrCast(@alignCast(context.?));
        for (self.leases, 0..) |lease, index| {
            if (self.fail_after == index) return error.PartialRestore;
            try visitor(visitor_context, lease);
        }
    }
};

fn restored4(domain: []const u8, id: u64, address: [4]u8, generation: u64, dns: u64, route: u64) RestoredLease {
    var full_address: [16]u8 = @splat(0);
    full_address[0..4].* = address;
    return .{
        .family = .ip4,
        .address = full_address,
        .publication = .{ .domain_id = id, .generation = generation, .route_valid_until_ns = route },
        .dns_expires_ns = dns,
        .domain = domain,
    };
}

fn restored6(domain: []const u8, id: u64, address: [16]u8, generation: u64, dns: u64, route: u64) RestoredLease {
    return .{
        .family = .ip6,
        .address = address,
        .publication = .{ .domain_id = id, .generation = generation, .route_valid_until_ns = route },
        .dns_expires_ns = dns,
        .domain = domain,
    };
}

test "FakeDNS restores dual-stack leases before allocation" {
    const leases = [_]RestoredLease{
        restored4("cached.example", 7, .{ 198, 18, 0, 1 }, 3, 80, 100),
        restored6("cached.example", 7, .{ 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 4, 80, 100),
    };
    var source: TestRestoreSource = .{ .leases = &leases };
    var store = try Store.initRestored(std.testing.allocator, test_config, .{
        .context = &source,
        .restore_fn = TestRestoreSource.restore,
    }, 10);
    defer store.deinit();

    var handle4 = store.lookupAt(.{ .ip4 = .{ .bytes = .{ 198, 18, 0, 1 }, .port = 443 } }, 20, std.Io.failing).?;
    defer handle4.release(std.Io.failing);
    const target6: net.IpAddress = .{ .ip6 = .{
        .bytes = leases[1].address,
        .port = 443,
        .interface = .none,
    } };
    var handle6 = store.lookupAt(target6, 20, std.Io.failing).?;
    defer handle6.release(std.Io.failing);
    try std.testing.expectEqualStrings("cached.example", handle4.domain());
    try std.testing.expectEqual(handle4.domainId(), handle6.domainId());
    try std.testing.expectEqual(@as(u64, 8), store.next_domain_id);
    try std.testing.expectEqualSlices(u8, &.{ 198, 18, 0, 2 }, &(try store.resolveAAt("new.example", 20, std.Io.failing)));
}

test "FakeDNS restore prunes expired input and safely reuses its address" {
    const leases = [_]RestoredLease{restored4("expired.example", 9, .{ 198, 18, 0, 1 }, 6, 50, 60)};
    var source: TestRestoreSource = .{ .leases = &leases };
    var store = try Store.initRestored(std.testing.allocator, test_config, .{
        .context = &source,
        .restore_fn = TestRestoreSource.restore,
    }, 60);
    defer store.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.leases4.count());
    try std.testing.expectEqualSlices(u8, &.{ 198, 18, 0, 1 }, &(try store.resolveAAt("replacement.example", 60, std.Io.failing)));
}

test "FakeDNS restore rejects domain id collisions and rolls back partial state" {
    const collisions = [_]RestoredLease{
        restored4("one.example", 7, .{ 198, 18, 0, 1 }, 1, 80, 100),
        restored6("two.example", 7, .{ 0xfc, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, 1, 80, 100),
    };
    var collision_source: TestRestoreSource = .{ .leases = &collisions };
    try std.testing.expectError(error.InvalidFakeDnsPersistentState, Store.initRestored(
        std.testing.allocator,
        test_config,
        .{ .context = &collision_source, .restore_fn = TestRestoreSource.restore },
        10,
    ));

    var partial_source: TestRestoreSource = .{ .leases = &collisions, .fail_after = 1 };
    try std.testing.expectError(error.PartialRestore, Store.initRestored(
        std.testing.allocator,
        test_config,
        .{ .context = &partial_source, .restore_fn = TestRestoreSource.restore },
        10,
    ));
}

test "FakeDNS normal deinit leaves publisher state intact" {
    var removals: usize = 0;
    const P = struct {
        fn remove(context: ?*anyopaque, address: [4]u8) void {
            _ = address;
            const count: *usize = @ptrCast(@alignCast(context.?));
            count.* += 1;
        }
    };
    var store = try Store.initWithPublisher(std.testing.allocator, test_config, .{
        .context = &removals,
        .remove4_fn = P.remove,
    });
    _ = try store.resolveAAt("cached.example", 0, std.Io.failing);
    store.deinit();
    try std.testing.expectEqual(@as(usize, 0), removals);
}

test "FakeDNS normalizes and safely holds a session lease" {
    var store = try Store.init(std.testing.allocator, test_config);
    defer store.deinit();
    const address = try store.resolveAAt("Example.COM.", 0, std.Io.failing);
    try std.testing.expectEqual(address, try store.resolveAAt("example.com", 1, std.Io.failing));
    const address6 = try store.resolveAAAAAt("example.com", 1, std.Io.failing);
    var handle = store.lookupAt(.{ .ip4 = .{ .bytes = address, .port = 443 } }, 2, std.Io.failing).?;
    defer handle.release(std.Io.failing);
    try std.testing.expectEqualStrings("example.com", handle.domain());
    try std.testing.expectEqual(@as(u64, 1), handle.domainId());
    const target6: net.IpAddress = .{ .ip6 = .{ .bytes = address6, .port = 443, .interface = .none } };
    var handle6 = store.lookupAt(target6, 2, std.Io.failing).?;
    defer handle6.release(std.Io.failing);
    try std.testing.expectEqual(handle.domainId(), handle6.domainId());
}

test "FakeDNS refreshes TTL and route validity" {
    var capture: Publication = undefined;
    const P = struct {
        fn publish(context: ?*anyopaque, address: [4]u8, value: LeasePublication) !void {
            _ = address;
            const output: *Publication = @ptrCast(@alignCast(context.?));
            output.* = value.dataplane;
        }
    };
    var store = try Store.initWithPublisher(std.testing.allocator, test_config, .{ .context = &capture, .publish4_fn = P.publish });
    defer store.deinit();
    const second = std.time.ns_per_s;
    _ = try store.resolveAAt("example.com", second, std.Io.failing);
    try std.testing.expectEqual(@as(u64, 16) * second, capture.route_valid_until_ns);
    _ = try store.resolveAAt("EXAMPLE.COM.", 7 * second, std.Io.failing);
    try std.testing.expectEqual(@as(u64, 22) * second, capture.route_valid_until_ns);
}

test "FakeDNS exhausts before grace and reuses with new generation" {
    var store = try Store.init(std.testing.allocator, test_config);
    defer store.deinit();
    const a = try store.resolveAAt("a.example", 0, std.Io.failing);
    _ = try store.resolveAAt("b.example", 0, std.Io.failing);
    try std.testing.expectError(error.FakeDnsPoolExhausted, store.resolveAAt("c.example", 14 * std.time.ns_per_s, std.Io.failing));
    const c = try store.resolveAAt("c.example", 15 * std.time.ns_per_s, std.Io.failing);
    try std.testing.expectEqual(a, c);
    var handle = store.lookupAt(.{ .ip4 = .{ .bytes = c, .port = 80 } }, 15 * std.time.ns_per_s, std.Io.failing).?;
    defer handle.release(std.Io.failing);
    try std.testing.expectEqualStrings("c.example", handle.domain());
    try std.testing.expectEqual(@as(u64, 2), handle.generation);
}

test "FakeDNS active flow prevents reuse and keeps domain alive" {
    var store = try Store.init(std.testing.allocator, test_config);
    defer store.deinit();
    const a = try store.resolveAAt("a.example", 0, std.Io.failing);
    const b = try store.resolveAAt("b.example", 0, std.Io.failing);
    var handle = store.lookupAt(.{ .ip4 = .{ .bytes = a, .port = 80 } }, 1, std.Io.failing).?;
    const c = try store.resolveAAt("c.example", 15 * std.time.ns_per_s, std.Io.failing);
    try std.testing.expectEqual(b, c);
    try std.testing.expectEqualStrings("a.example", handle.domain());
    try std.testing.expectError(error.FakeDnsPoolExhausted, store.resolveAAt("d.example", 15 * std.time.ns_per_s, std.Io.failing));
    handle.release(std.Io.failing);
    try std.testing.expectEqual(a, try store.resolveAAt("d.example", 15 * std.time.ns_per_s, std.Io.failing));
}

test "FakeDNS IPv6 generation increments" {
    var cfg = test_config;
    cfg.ip_pool6 = "2001:db8::/127";
    var store = try Store.init(std.testing.allocator, cfg);
    defer store.deinit();
    const a = try store.resolveAAAAAt("a.example", 0, std.Io.failing);
    _ = try store.resolveAAAAAt("b.example", 0, std.Io.failing);
    const c = try store.resolveAAAAAt("c.example", 15 * std.time.ns_per_s, std.Io.failing);
    try std.testing.expectEqual(a, c);
    const target: net.IpAddress = .{ .ip6 = .{ .bytes = c, .port = 443, .interface = .none } };
    var handle = store.lookupAt(target, 15 * std.time.ns_per_s, std.Io.failing).?;
    defer handle.release(std.Io.failing);
    try std.testing.expectEqual(@as(u64, 2), handle.generation);
    try std.testing.expect(store.contains(target));
}

test "FakeDNS publication failure rolls back allocation" {
    const P = struct {
        fn fail(context: ?*anyopaque, address: [4]u8, value: LeasePublication) !void {
            _ = context;
            _ = address;
            _ = value;
            return error.PublishFailed;
        }
    };
    var store = try Store.initWithPublisher(std.testing.allocator, test_config, .{ .publish4_fn = P.fail });
    defer store.deinit();
    try std.testing.expectError(error.PublishFailed, store.resolveAAt("a.example", 0, std.Io.failing));
    try std.testing.expectEqual(@as(usize, 0), store.domains.count());
    try std.testing.expectEqual(@as(usize, 0), store.leases4.count());
}

test "FakeDNS publication failure rolls back TTL refresh" {
    const State = struct { fail: bool = false };
    const P = struct {
        fn publish(context: ?*anyopaque, address: [4]u8, value: LeasePublication) !void {
            _ = address;
            _ = value;
            const state: *State = @ptrCast(@alignCast(context.?));
            if (state.fail) return error.PublishFailed;
        }
    };
    var state: State = .{};
    var store = try Store.initWithPublisher(std.testing.allocator, test_config, .{
        .context = &state,
        .publish4_fn = P.publish,
    });
    defer store.deinit();
    const address = try store.resolveAAt("a.example", 0, std.Io.failing);
    const before = store.leases4.get(bytesToIp(address)).?.reuse_after_ns;
    state.fail = true;
    try std.testing.expectError(error.PublishFailed, store.resolveAAt("a.example", 30 * std.time.ns_per_s, std.Io.failing));
    try std.testing.expectEqual(before, store.leases4.get(bytesToIp(address)).?.reuse_after_ns);
}

test "FakeDNS churn keeps domain storage bounded by live leases" {
    var store = try Store.init(std.testing.allocator, test_config);
    defer store.deinit();
    var name_buffer: [32]u8 = undefined;
    var now: u64 = 0;
    for (0..100) |index| {
        const name = try std.fmt.bufPrint(&name_buffer, "domain-{d}.example", .{index});
        _ = try store.resolveAAt(name, now, std.Io.failing);
        now += 15 * std.time.ns_per_s;
    }
    try std.testing.expectEqual(@as(usize, 2), store.leases4.count());
    try std.testing.expectEqual(@as(usize, 2), store.domains.count());
}

test "FakeDNS allocation is leak-free on failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var store = try Store.init(allocator, test_config);
            defer store.deinit();
            _ = try store.resolveAAt("example.com", 0, std.Io.failing);
            _ = try store.resolveAAAAAt("example.com", 0, std.Io.failing);
        }
    }.run, .{});
}
