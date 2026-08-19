const std = @import("std");

pub const max_mtu = 1500;
pub const udp_header_len = 8;

pub const Version = enum(u8) {
    ip4 = 4,
    ip6 = 6,
};

pub fn payloadLimit(version: Version) usize {
    return switch (version) {
        .ip4 => max_mtu - 20 - udp_header_len,
        .ip6 => max_mtu - 40 - udp_header_len,
    };
}

pub const FlowKey = struct {
    version: Version,
    source: [16]u8,
    destination: [16]u8,
    source_port: u16,
    destination_port: u16,

    pub fn eql(a: FlowKey, b: FlowKey) bool {
        return a.version == b.version and
            a.source_port == b.source_port and
            a.destination_port == b.destination_port and
            std.mem.eql(u8, &a.source, &b.source) and
            std.mem.eql(u8, &a.destination, &b.destination);
    }

    pub fn hash(self: FlowKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        hasher.update(&.{@intFromEnum(self.version)});
        hasher.update(&self.source);
        hasher.update(&self.destination);
        var ports: [4]u8 = undefined;
        std.mem.writeInt(u16, ports[0..2], self.source_port, .big);
        std.mem.writeInt(u16, ports[2..4], self.destination_port, .big);
        hasher.update(&ports);
        return hasher.final();
    }

    pub fn reverse(self: FlowKey) FlowKey {
        return .{
            .version = self.version,
            .source = self.destination,
            .destination = self.source,
            .source_port = self.destination_port,
            .destination_port = self.source_port,
        };
    }
};

pub const Datagram = struct {
    key: FlowKey,
    payload: []const u8,
};

pub const ParseError = error{
    PacketTooShort,
    PacketTooLarge,
    InvalidIpVersion,
    InvalidIpHeader,
    InvalidIpChecksum,
    FragmentedPacket,
    UnsupportedProtocol,
    UnsupportedIpv6Extension,
    InvalidUdpHeader,
    InvalidUdpChecksum,
};

pub fn parse(bytes: []const u8) ParseError!Datagram {
    if (bytes.len == 0) return error.PacketTooShort;
    if (bytes.len > max_mtu) return error.PacketTooLarge;
    return switch (bytes[0] >> 4) {
        4 => parse4(bytes),
        6 => parse6(bytes),
        else => error.InvalidIpVersion,
    };
}

fn parse4(bytes: []const u8) ParseError!Datagram {
    if (bytes.len < 20) return error.PacketTooShort;
    const ip_header_len = @as(usize, bytes[0] & 0x0f) * 4;
    if (ip_header_len < 20 or ip_header_len > bytes.len) return error.InvalidIpHeader;
    const total_len: usize = std.mem.readInt(u16, bytes[2..4], .big);
    if (total_len != bytes.len or total_len < ip_header_len + udp_header_len) return error.InvalidIpHeader;
    if (internetChecksum(bytes[0..ip_header_len]) != 0) return error.InvalidIpChecksum;
    if ((std.mem.readInt(u16, bytes[6..8], .big) & 0x3fff) != 0) return error.FragmentedPacket;
    if (bytes[9] != 17) return error.UnsupportedProtocol;

    var source = [_]u8{0} ** 16;
    var destination = [_]u8{0} ** 16;
    @memcpy(source[0..4], bytes[12..16]);
    @memcpy(destination[0..4], bytes[16..20]);
    const udp = bytes[ip_header_len..];
    const parsed = try parseUdp(.{
        .version = .ip4,
        .source = source,
        .destination = destination,
        .source_port = 0,
        .destination_port = 0,
    }, udp);
    const checksum = std.mem.readInt(u16, udp[6..8], .big);
    if (checksum != 0 and udpChecksum(.ip4, source, destination, udp) != 0) {
        return error.InvalidUdpChecksum;
    }
    return parsed;
}

fn parse6(bytes: []const u8) ParseError!Datagram {
    if (bytes.len < 40) return error.PacketTooShort;
    const payload_len: usize = std.mem.readInt(u16, bytes[4..6], .big);
    if (payload_len == 0) return error.InvalidIpHeader;
    const total_len = 40 + payload_len;
    if (total_len != bytes.len or payload_len < udp_header_len) return error.InvalidIpHeader;
    if (bytes[6] != 17) return switch (bytes[6]) {
        0, 43, 60, 51, 50 => error.UnsupportedIpv6Extension,
        44 => error.FragmentedPacket,
        else => error.UnsupportedProtocol,
    };

    const source = bytes[8..24].*;
    const destination = bytes[24..40].*;
    const udp = bytes[40..];
    const parsed = try parseUdp(.{
        .version = .ip6,
        .source = source,
        .destination = destination,
        .source_port = 0,
        .destination_port = 0,
    }, udp);
    if (std.mem.readInt(u16, udp[6..8], .big) == 0 or
        udpChecksum(.ip6, source, destination, udp) != 0)
    {
        return error.InvalidUdpChecksum;
    }
    return parsed;
}

fn parseUdp(key_template: FlowKey, udp: []const u8) ParseError!Datagram {
    if (udp.len < udp_header_len) return error.InvalidUdpHeader;
    const declared_len: usize = std.mem.readInt(u16, udp[4..6], .big);
    if (declared_len != udp.len or declared_len < udp_header_len) return error.InvalidUdpHeader;
    var key = key_template;
    key.source_port = std.mem.readInt(u16, udp[0..2], .big);
    key.destination_port = std.mem.readInt(u16, udp[2..4], .big);
    return .{ .key = key, .payload = udp[udp_header_len..] };
}

pub fn build(output: []u8, key: FlowKey, payload: []const u8, identification: u16) ![]const u8 {
    const ip_header_len: usize = if (key.version == .ip4) 20 else 40;
    const udp_len = udp_header_len + payload.len;
    const total_len = ip_header_len + udp_len;
    if (total_len > output.len or total_len > max_mtu or udp_len > std.math.maxInt(u16)) {
        return error.PacketTooLarge;
    }

    const result = output[0..total_len];
    @memset(result, 0);
    if (key.version == .ip4) {
        result[0] = 0x45;
        std.mem.writeInt(u16, result[2..4], @intCast(total_len), .big);
        std.mem.writeInt(u16, result[4..6], identification, .big);
        std.mem.writeInt(u16, result[6..8], 0x4000, .big);
        result[8] = 64;
        result[9] = 17;
        @memcpy(result[12..16], key.source[0..4]);
        @memcpy(result[16..20], key.destination[0..4]);
        std.mem.writeInt(u16, result[10..12], internetChecksum(result[0..20]), .big);
    } else {
        result[0] = 0x60;
        std.mem.writeInt(u16, result[4..6], @intCast(udp_len), .big);
        result[6] = 17;
        result[7] = 64;
        @memcpy(result[8..24], &key.source);
        @memcpy(result[24..40], &key.destination);
    }

    const udp = result[ip_header_len..];
    std.mem.writeInt(u16, udp[0..2], key.source_port, .big);
    std.mem.writeInt(u16, udp[2..4], key.destination_port, .big);
    std.mem.writeInt(u16, udp[4..6], @intCast(udp_len), .big);
    @memcpy(udp[udp_header_len..], payload);
    var checksum = udpChecksum(key.version, key.source, key.destination, udp);
    if (checksum == 0) checksum = 0xffff;
    std.mem.writeInt(u16, udp[6..8], checksum, .big);
    return result;
}

fn udpChecksum(version: Version, source: [16]u8, destination: [16]u8, udp: []const u8) u16 {
    var sum: u32 = 0;
    switch (version) {
        .ip4 => {
            sum = checksumAdd(sum, source[0..4]);
            sum = checksumAdd(sum, destination[0..4]);
            sum += 17;
            sum += @intCast(udp.len);
        },
        .ip6 => {
            sum = checksumAdd(sum, &source);
            sum = checksumAdd(sum, &destination);
            sum += @intCast(udp.len);
            sum += 17;
        },
    }
    return checksumFinish(checksumAdd(sum, udp));
}

fn internetChecksum(bytes: []const u8) u16 {
    return checksumFinish(checksumAdd(0, bytes));
}

fn checksumAdd(initial: u32, bytes: []const u8) u32 {
    var sum = initial;
    var offset: usize = 0;
    while (offset + 1 < bytes.len) : (offset += 2) {
        sum += (@as(u32, bytes[offset]) << 8) | bytes[offset + 1];
    }
    if (offset < bytes.len) sum += @as(u32, bytes[offset]) << 8;
    return sum;
}

fn checksumFinish(initial: u32) u16 {
    var sum = initial;
    while (sum >> 16 != 0) sum = (sum & 0xffff) + (sum >> 16);
    return @truncate(~sum);
}

fn testKey(version: Version) FlowKey {
    return switch (version) {
        .ip4 => .{
            .version = .ip4,
            .source = .{ 192, 0, 2, 10 } ++ ([_]u8{0} ** 12),
            .destination = .{ 198, 51, 100, 20 } ++ ([_]u8{0} ** 12),
            .source_port = 53000,
            .destination_port = 53,
        },
        .ip6 => .{
            .version = .ip6,
            .source = .{ 0x20, 1, 0x0d, 0xb8 } ++ ([_]u8{0} ** 12),
            .destination = .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .source_port = 53000,
            .destination_port = 53,
        },
    };
}

test "builds and parses IPv4 UDP" {
    const key = testKey(.ip4);
    var buffer: [max_mtu]u8 = undefined;
    const bytes = try build(&buffer, key, "dns-query", 17);
    const parsed = try parse(bytes);
    try std.testing.expect(key.eql(parsed.key));
    try std.testing.expectEqualStrings("dns-query", parsed.payload);
}

test "IPv4 accepts an omitted UDP checksum" {
    const key = testKey(.ip4);
    var buffer: [max_mtu]u8 = undefined;
    const bytes = try build(&buffer, key, "payload", 1);
    @memset(buffer[26..28], 0);
    _ = try parse(bytes);
}

test "rejects a bad nonzero IPv4 UDP checksum" {
    const key = testKey(.ip4);
    var buffer: [max_mtu]u8 = undefined;
    const bytes = try build(&buffer, key, "payload", 1);
    buffer[28] ^= 0x80;
    try std.testing.expectError(error.InvalidUdpChecksum, parse(bytes));
}

test "builds and parses IPv6 UDP with mandatory checksum" {
    const key = testKey(.ip6);
    var buffer: [max_mtu]u8 = undefined;
    const bytes = try build(&buffer, key, "dns6", 0);
    const parsed = try parse(bytes);
    try std.testing.expect(key.eql(parsed.key));
    try std.testing.expectEqualStrings("dns6", parsed.payload);

    @memset(buffer[46..48], 0);
    try std.testing.expectError(error.InvalidUdpChecksum, parse(bytes));
}

test "rejects fragments and IPv6 extension headers" {
    const key4 = testKey(.ip4);
    var buffer4: [max_mtu]u8 = undefined;
    const bytes4 = try build(&buffer4, key4, "x", 1);
    buffer4[6] = 0x20;
    @memset(buffer4[10..12], 0);
    std.mem.writeInt(u16, buffer4[10..12], internetChecksum(buffer4[0..20]), .big);
    try std.testing.expectError(error.FragmentedPacket, parse(bytes4));

    const key6 = testKey(.ip6);
    var buffer6: [max_mtu]u8 = undefined;
    const bytes6 = try build(&buffer6, key6, "x", 0);
    buffer6[6] = 44;
    try std.testing.expectError(error.FragmentedPacket, parse(bytes6));
    buffer6[6] = 0;
    try std.testing.expectError(error.UnsupportedIpv6Extension, parse(bytes6));
}

test "rejects malformed IP and UDP lengths" {
    const key = testKey(.ip4);
    var buffer: [max_mtu]u8 = undefined;
    const bytes = try build(&buffer, key, "payload", 1);

    std.mem.writeInt(u16, buffer[24..26], 8, .big);
    try std.testing.expectError(error.InvalidUdpHeader, parse(bytes));

    _ = try build(&buffer, key, "payload", 1);
    std.mem.writeInt(u16, buffer[2..4], @intCast(bytes.len - 1), .big);
    @memset(buffer[10..12], 0);
    std.mem.writeInt(u16, buffer[10..12], internetChecksum(buffer[0..20]), .big);
    try std.testing.expectError(error.InvalidIpHeader, parse(bytes));
}

test "enforces MTU payload limits" {
    var buffer: [max_mtu]u8 = undefined;
    const payload4 = [_]u8{0xaa} ** payloadLimit(.ip4);
    const bytes4 = try build(&buffer, testKey(.ip4), &payload4, 1);
    try std.testing.expectEqual(@as(usize, max_mtu), bytes4.len);
    try std.testing.expectError(error.PacketTooLarge, build(&buffer, testKey(.ip6), &payload4, 0));
}
