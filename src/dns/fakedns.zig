const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../config/mod.zig");

pub const Error = error{
    InvalidFakeDnsPool,
    FakeDnsPoolExhausted,
    DomainTooLong,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    pool_base: u32,
    prefix_len: u8,
    usable_count: u32,
    next_offset: u32,
    pool6_base: [16]u8,
    pool6_prefix_len: u8,
    pool6_usable_count: u64,
    pool6_next_offset: u64,
    mutex: Io.Mutex = .init,
    domain_to_ip: std.StringHashMap(u32),
    ip_to_domain: std.AutoHashMap(u32, []const u8),
    domain_to_ip6: std.StringHashMap([16]u8),
    ip6_to_domain: std.AutoHashMap([16]u8, []const u8),

    pub fn init(allocator: std.mem.Allocator, cfg: config.FakeDnsConfig) !Store {
        const pool = try parsePool(cfg.ip_pool);
        const pool6 = try parsePool6(cfg.ip_pool6);
        return .{
            .allocator = allocator,
            .pool_base = pool.base,
            .prefix_len = pool.prefix_len,
            .usable_count = pool.usable_count,
            .next_offset = 1,
            .pool6_base = pool6.base,
            .pool6_prefix_len = pool6.prefix_len,
            .pool6_usable_count = pool6.usable_count,
            .pool6_next_offset = 0,
            .domain_to_ip = std.StringHashMap(u32).init(allocator),
            .ip_to_domain = std.AutoHashMap(u32, []const u8).init(allocator),
            .domain_to_ip6 = std.StringHashMap([16]u8).init(allocator),
            .ip6_to_domain = std.AutoHashMap([16]u8, []const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Store) void {
        var it = self.domain_to_ip.iterator();
        while (it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.domain_to_ip.deinit();
        self.ip_to_domain.deinit();
        var ip6_it = self.domain_to_ip6.iterator();
        while (ip6_it.next()) |entry| self.allocator.free(entry.key_ptr.*);
        self.domain_to_ip6.deinit();
        self.ip6_to_domain.deinit();
        self.* = undefined;
    }

    pub fn resolveA(self: *Store, domain: []const u8, io: Io) ![4]u8 {
        var normalized_buffer: [net.HostName.max_len]u8 = undefined;
        const normalized = try normalizeDomain(&normalized_buffer, domain);

        try self.mutex.lock(io);
        defer self.mutex.unlock(io);

        if (self.domain_to_ip.get(normalized)) |ip| {
            return ipToBytes(ip);
        }

        const owned = try self.allocator.dupe(u8, normalized);
        errdefer self.allocator.free(owned);
        const ip = try self.nextIp();
        if (self.ip_to_domain.fetchRemove(ip)) |old| {
            _ = self.domain_to_ip.remove(old.value);
            self.allocator.free(old.value);
        }

        try self.domain_to_ip.put(owned, ip);
        errdefer _ = self.domain_to_ip.remove(owned);
        try self.ip_to_domain.put(ip, owned);
        return ipToBytes(ip);
    }

    pub fn resolveAAAA(self: *Store, domain: []const u8, io: Io) ![16]u8 {
        var normalized_buffer: [net.HostName.max_len]u8 = undefined;
        const normalized = try normalizeDomain(&normalized_buffer, domain);

        try self.mutex.lock(io);
        defer self.mutex.unlock(io);

        if (self.domain_to_ip6.get(normalized)) |ip| {
            return ip;
        }

        const owned = try self.allocator.dupe(u8, normalized);
        errdefer self.allocator.free(owned);
        const ip = try self.nextIp6();
        if (self.ip6_to_domain.fetchRemove(ip)) |old| {
            _ = self.domain_to_ip6.remove(old.value);
            self.allocator.free(old.value);
        }

        try self.domain_to_ip6.put(owned, ip);
        errdefer _ = self.domain_to_ip6.remove(owned);
        try self.ip6_to_domain.put(ip, owned);
        return ip;
    }

    pub fn lookup(self: *Store, address: net.IpAddress, io: Io) ?[]const u8 {
        self.mutex.lock(io) catch return null;
        defer self.mutex.unlock(io);
        return switch (address) {
            .ip4 => |ip4| self.ip_to_domain.get(bytesToIp(ip4.bytes)),
            .ip6 => |ip6| self.ip6_to_domain.get(ip6.bytes),
        };
    }

    pub fn contains(self: *const Store, address: net.IpAddress) bool {
        return switch (address) {
            .ip4 => |ip4| blk: {
                const ip = bytesToIp(ip4.bytes);
                const mask = prefixMask(self.prefix_len);
                break :blk (ip & mask) == self.pool_base;
            },
            .ip6 => |ip6| prefixMatches6(ip6.bytes, self.pool6_base, self.pool6_prefix_len),
        };
    }

    fn nextIp(self: *Store) !u32 {
        if (self.usable_count == 0) return error.FakeDnsPoolExhausted;
        const ip = self.pool_base + self.next_offset;
        self.next_offset += 1;
        if (self.next_offset > self.usable_count) self.next_offset = 1;
        return ip;
    }

    fn nextIp6(self: *Store) ![16]u8 {
        if (self.pool6_usable_count == 0) return error.FakeDnsPoolExhausted;
        const ip = addOffset6(self.pool6_base, self.pool6_next_offset);
        self.pool6_next_offset += 1;
        if (self.pool6_next_offset >= self.pool6_usable_count) self.pool6_next_offset = 0;
        return ip;
    }
};

fn parsePool(text: []const u8) !struct { base: u32, prefix_len: u8, usable_count: u32 } {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidFakeDnsPool;
    const address_text = text[0..slash];
    const prefix_len = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return error.InvalidFakeDnsPool;
    if (prefix_len > 30) return error.InvalidFakeDnsPool;

    const parsed = net.IpAddress.parse(address_text, 0) catch return error.InvalidFakeDnsPool;
    const address = switch (parsed) {
        .ip4 => |ip4| bytesToIp(ip4.bytes),
        .ip6 => return error.InvalidFakeDnsPool,
    };
    const mask = prefixMask(prefix_len);
    const total: u64 = @as(u64, 1) << @intCast(32 - prefix_len);
    if (total <= 2) return error.InvalidFakeDnsPool;
    return .{
        .base = address & mask,
        .prefix_len = prefix_len,
        .usable_count = @intCast(total - 2),
    };
}

fn prefixMask(prefix_len: u8) u32 {
    if (prefix_len == 0) return 0;
    return std.math.shl(u32, std.math.maxInt(u32), 32 - prefix_len);
}

fn parsePool6(text: []const u8) !struct { base: [16]u8, prefix_len: u8, usable_count: u64 } {
    const slash = std.mem.indexOfScalar(u8, text, '/') orelse return error.InvalidFakeDnsPool;
    const address_text = text[0..slash];
    const prefix_len = std.fmt.parseInt(u8, text[slash + 1 ..], 10) catch return error.InvalidFakeDnsPool;
    if (prefix_len > 128) return error.InvalidFakeDnsPool;

    const parsed = net.IpAddress.parse(address_text, 0) catch return error.InvalidFakeDnsPool;
    var base = switch (parsed) {
        .ip4 => return error.InvalidFakeDnsPool,
        .ip6 => |ip6| ip6.bytes,
    };
    maskNetwork6(&base, prefix_len);

    const host_bits: u8 = 128 - prefix_len;
    const usable_count = if (host_bits >= 64)
        std.math.maxInt(u64)
    else
        @as(u64, 1) << @intCast(host_bits);
    return .{ .base = base, .prefix_len = prefix_len, .usable_count = usable_count };
}

fn maskNetwork6(address: *[16]u8, prefix_len: u8) void {
    const full_bytes = prefix_len / 8;
    const remaining_bits = prefix_len % 8;
    var index: usize = full_bytes;
    if (remaining_bits != 0) {
        const shift: u3 = @intCast(8 - remaining_bits);
        address[index] &= @as(u8, 0xff) << shift;
        index += 1;
    }
    @memset(address[index..], 0);
}

fn prefixMatches6(address: [16]u8, network: [16]u8, prefix_len: u8) bool {
    const full_bytes = prefix_len / 8;
    if (!std.mem.eql(u8, address[0..full_bytes], network[0..full_bytes])) return false;
    const remaining_bits = prefix_len % 8;
    if (remaining_bits == 0) return true;
    const shift: u3 = @intCast(8 - remaining_bits);
    const mask = @as(u8, 0xff) << shift;
    return (address[full_bytes] & mask) == (network[full_bytes] & mask);
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

test "allocates and reverse maps fake IPv4 addresses" {
    var store = try Store.init(std.testing.allocator, .{
        .ip_pool = "198.18.0.0/30",
        .ip_pool6 = "fc00::/126",
        .ttl = 60,
    });
    defer store.deinit();

    const first = try store.resolveA("Example.COM.", std.Io.failing);
    try std.testing.expectEqualSlices(u8, &.{ 198, 18, 0, 1 }, &first);

    const again = try store.resolveA("example.com", std.Io.failing);
    try std.testing.expectEqualSlices(u8, &first, &again);

    const domain = store.lookup(.{ .ip4 = .{ .bytes = first, .port = 443 } }, std.Io.failing).?;
    try std.testing.expectEqualStrings("example.com", domain);
}

test "cached fake addresses do not allocate" {
    var store = try Store.init(std.testing.allocator, .{
        .ip_pool = "198.18.0.0/30",
        .ip_pool6 = "fc00::/126",
        .ttl = 60,
    });
    defer store.deinit();

    const ipv4 = try store.resolveA("example.com", std.Io.failing);
    const ipv6 = try store.resolveAAAA("example.com", std.Io.failing);

    const allocator = store.allocator;
    store.allocator = std.testing.failing_allocator;
    defer store.allocator = allocator;

    try std.testing.expectEqual(ipv4, try store.resolveA("Example.COM.", std.Io.failing));
    try std.testing.expectEqual(ipv6, try store.resolveAAAA("Example.COM.", std.Io.failing));
}

test "fake address insertion is leak-free on allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var store = try Store.init(allocator, .{
                .ip_pool = "198.18.0.0/30",
                .ip_pool6 = "fc00::/126",
                .ttl = 60,
            });
            defer store.deinit();

            _ = try store.resolveA("example.com", std.Io.failing);
            _ = try store.resolveAAAA("example.com", std.Io.failing);
        }
    }.run, .{});
}

test "wraps fake pool and evicts reverse mapping" {
    var store = try Store.init(std.testing.allocator, .{
        .ip_pool = "198.18.0.0/30",
        .ip_pool6 = "fc00::/126",
        .ttl = 60,
    });
    defer store.deinit();

    const a = try store.resolveA("a.example", std.Io.failing);
    _ = try store.resolveA("b.example", std.Io.failing);
    const c = try store.resolveA("c.example", std.Io.failing);

    try std.testing.expectEqualSlices(u8, &a, &c);
    try std.testing.expect(store.lookup(.{ .ip4 = .{ .bytes = a, .port = 80 } }, std.Io.failing) != null);
}

test "allocates and reverse maps fake IPv6 addresses" {
    var store = try Store.init(std.testing.allocator, .{
        .ip_pool = "198.18.0.0/30",
        .ip_pool6 = "fc00::/126",
        .ttl = 60,
    });
    defer store.deinit();

    const first = try store.resolveAAAA("Example.COM.", std.Io.failing);
    try std.testing.expectEqualSlices(u8, &([_]u8{0xfc} ++ [_]u8{0} ** 15), &first);

    const again = try store.resolveAAAA("example.com", std.Io.failing);
    try std.testing.expectEqualSlices(u8, &first, &again);

    const address: net.IpAddress = .{ .ip6 = .{
        .bytes = first,
        .port = 443,
        .interface = .none,
    } };
    try std.testing.expectEqualStrings("example.com", store.lookup(address, std.Io.failing).?);
    try std.testing.expect(store.contains(address));
}

test "wraps fake IPv6 pool and evicts reverse mapping" {
    var store = try Store.init(std.testing.allocator, .{
        .ip_pool = "198.18.0.0/30",
        .ip_pool6 = "2001:db8::/127",
        .ttl = 60,
    });
    defer store.deinit();

    const a = try store.resolveAAAA("a.example", std.Io.failing);
    _ = try store.resolveAAAA("b.example", std.Io.failing);
    const c = try store.resolveAAAA("c.example", std.Io.failing);

    try std.testing.expectEqualSlices(u8, &a, &c);
    const address: net.IpAddress = .{ .ip6 = .{
        .bytes = a,
        .port = 80,
        .interface = .none,
    } };
    try std.testing.expectEqualStrings("c.example", store.lookup(address, std.Io.failing).?);
}
