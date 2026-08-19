const std = @import("std");

pub const max_mtu = 1500;
pub const max_tcp_payload = max_mtu - 40;

pub const Version = enum(u8) {
    ip4 = 4,
    ip6 = 6,
};

pub fn tcpPayloadLimit(version: Version) usize {
    return tcpPayloadLimitForMtu(version, max_mtu);
}

pub fn tcpPayloadLimitForMtu(version: Version, mtu: u16) usize {
    const header_len: u16 = switch (version) {
        .ip4 => 20 + 20,
        .ip6 => 40 + 20,
    };
    if (mtu <= header_len) return 0;
    return mtu - header_len;
}

pub fn minimumMtu(version: Version) u16 {
    return switch (version) {
        .ip4 => 40,
        .ip6 => 60,
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
};

pub const Flags = packed struct(u8) {
    fin: bool = false,
    syn: bool = false,
    rst: bool = false,
    psh: bool = false,
    ack: bool = false,
    urg: bool = false,
    ece: bool = false,
    cwr: bool = false,
};

pub const Segment = struct {
    key: FlowKey,
    sequence: u32,
    acknowledgment: u32,
    flags: Flags,
    window: u16,
    maximum_segment_size: ?u16,
    payload: []const u8,
};

pub const ParseError = error{
    PacketTooShort,
    InvalidIpVersion,
    InvalidIpHeader,
    InvalidIpChecksum,
    FragmentedPacket,
    UnsupportedProtocol,
    UnsupportedIpv6Extension,
    InvalidTcpHeader,
    InvalidTcpChecksum,
};

pub fn parse(bytes: []const u8) ParseError!Segment {
    if (bytes.len == 0) return error.PacketTooShort;
    return switch (bytes[0] >> 4) {
        4 => parse4(bytes),
        6 => parse6(bytes),
        else => error.InvalidIpVersion,
    };
}

fn parse4(bytes: []const u8) ParseError!Segment {
    if (bytes.len < 20) return error.PacketTooShort;
    const ip_header_len = @as(usize, bytes[0] & 0x0f) * 4;
    if (ip_header_len < 20 or ip_header_len > bytes.len) return error.InvalidIpHeader;
    const total_len = std.mem.readInt(u16, bytes[2..4], .big);
    if (total_len < ip_header_len or total_len > bytes.len) return error.InvalidIpHeader;
    if (internetChecksum(bytes[0..ip_header_len]) != 0) return error.InvalidIpChecksum;
    if ((std.mem.readInt(u16, bytes[6..8], .big) & 0x3fff) != 0) return error.FragmentedPacket;
    if (bytes[9] != 6) return error.UnsupportedProtocol;

    var source = [_]u8{0} ** 16;
    var destination = [_]u8{0} ** 16;
    @memcpy(source[0..4], bytes[12..16]);
    @memcpy(destination[0..4], bytes[16..20]);
    const tcp = bytes[ip_header_len..total_len];
    if (tcpChecksum(.ip4, source, destination, tcp) != 0) return error.InvalidTcpChecksum;
    return parseTcp(.{
        .version = .ip4,
        .source = source,
        .destination = destination,
        .source_port = 0,
        .destination_port = 0,
    }, tcp);
}

fn parse6(bytes: []const u8) ParseError!Segment {
    if (bytes.len < 40) return error.PacketTooShort;
    const payload_len = std.mem.readInt(u16, bytes[4..6], .big);
    const total_len = 40 + @as(usize, payload_len);
    if (total_len > bytes.len) return error.InvalidIpHeader;
    if (bytes[6] != 6) return if (bytes[6] == 17)
        error.UnsupportedProtocol
    else
        error.UnsupportedIpv6Extension;

    const source = bytes[8..24].*;
    const destination = bytes[24..40].*;
    const tcp = bytes[40..total_len];
    if (tcpChecksum(.ip6, source, destination, tcp) != 0) return error.InvalidTcpChecksum;
    return parseTcp(.{
        .version = .ip6,
        .source = source,
        .destination = destination,
        .source_port = 0,
        .destination_port = 0,
    }, tcp);
}

fn parseTcp(key_template: FlowKey, tcp: []const u8) ParseError!Segment {
    if (tcp.len < 20) return error.InvalidTcpHeader;
    const tcp_header_len = @as(usize, tcp[12] >> 4) * 4;
    if (tcp_header_len < 20 or tcp_header_len > tcp.len) return error.InvalidTcpHeader;
    var key = key_template;
    key.source_port = std.mem.readInt(u16, tcp[0..2], .big);
    key.destination_port = std.mem.readInt(u16, tcp[2..4], .big);
    return .{
        .key = key,
        .sequence = std.mem.readInt(u32, tcp[4..8], .big),
        .acknowledgment = std.mem.readInt(u32, tcp[8..12], .big),
        .flags = @bitCast(tcp[13]),
        .window = std.mem.readInt(u16, tcp[14..16], .big),
        .maximum_segment_size = try parseMaximumSegmentSize(tcp[20..tcp_header_len]),
        .payload = tcp[tcp_header_len..],
    };
}

fn parseMaximumSegmentSize(options: []const u8) ParseError!?u16 {
    var offset: usize = 0;
    while (offset < options.len) {
        const kind = options[offset];
        if (kind == 0) break;
        if (kind == 1) {
            offset += 1;
            continue;
        }
        if (offset + 2 > options.len) return error.InvalidTcpHeader;
        const len = options[offset + 1];
        if (len < 2 or offset + len > options.len) return error.InvalidTcpHeader;
        if (kind == 2) {
            if (len != 4) return error.InvalidTcpHeader;
            return std.mem.readInt(u16, options[offset + 2 ..][0..2], .big);
        }
        offset += len;
    }
    return null;
}

pub fn build(
    output: []u8,
    key: FlowKey,
    sequence: u32,
    acknowledgment: u32,
    flags: Flags,
    window: u16,
    payload: []const u8,
    identification: u16,
) ![]const u8 {
    return buildForMtu(output, key, sequence, acknowledgment, flags, window, payload, identification, max_mtu);
}

pub fn buildForMtu(
    output: []u8,
    key: FlowKey,
    sequence: u32,
    acknowledgment: u32,
    flags: Flags,
    window: u16,
    payload: []const u8,
    identification: u16,
    mtu: u16,
) ![]const u8 {
    const ip_header_len: usize = if (key.version == .ip4) 20 else 40;
    const tcp_header_len: usize = if (flags.syn) 24 else 20;
    const total_len = ip_header_len + tcp_header_len + payload.len;
    if (mtu > max_mtu or mtu < minimumMtu(key.version)) return error.InvalidMtu;
    if (total_len > output.len or total_len > mtu) return error.PacketTooLarge;
    const packet = output[0..total_len];
    @memset(packet, 0);

    if (key.version == .ip4) {
        packet[0] = 0x45;
        std.mem.writeInt(u16, packet[2..4], @intCast(total_len), .big);
        std.mem.writeInt(u16, packet[4..6], identification, .big);
        std.mem.writeInt(u16, packet[6..8], 0x4000, .big);
        packet[8] = 64;
        packet[9] = 6;
        @memcpy(packet[12..16], key.destination[0..4]);
        @memcpy(packet[16..20], key.source[0..4]);
        std.mem.writeInt(u16, packet[10..12], internetChecksum(packet[0..20]), .big);
    } else {
        packet[0] = 0x60;
        std.mem.writeInt(u16, packet[4..6], @intCast(tcp_header_len + payload.len), .big);
        packet[6] = 6;
        packet[7] = 64;
        @memcpy(packet[8..24], &key.destination);
        @memcpy(packet[24..40], &key.source);
    }

    const tcp = packet[ip_header_len..];
    std.mem.writeInt(u16, tcp[0..2], key.destination_port, .big);
    std.mem.writeInt(u16, tcp[2..4], key.source_port, .big);
    std.mem.writeInt(u32, tcp[4..8], sequence, .big);
    std.mem.writeInt(u32, tcp[8..12], acknowledgment, .big);
    tcp[12] = @as(u8, @intCast(tcp_header_len / 4)) << 4;
    tcp[13] = @bitCast(flags);
    std.mem.writeInt(u16, tcp[14..16], window, .big);
    if (flags.syn) {
        tcp[20] = 2;
        tcp[21] = 4;
        const mss: u16 = @intCast(tcpPayloadLimitForMtu(key.version, mtu));
        std.mem.writeInt(u16, tcp[22..24], mss, .big);
    }
    @memcpy(tcp[tcp_header_len..], payload);
    std.mem.writeInt(
        u16,
        tcp[16..18],
        tcpChecksum(key.version, key.destination, key.source, tcp),
        .big,
    );
    return packet;
}

fn tcpChecksum(version: Version, source: [16]u8, destination: [16]u8, tcp: []const u8) u16 {
    var sum: u32 = 0;
    switch (version) {
        .ip4 => {
            sum = checksumAdd(sum, source[0..4]);
            sum = checksumAdd(sum, destination[0..4]);
            sum += 6;
            sum += @intCast(tcp.len);
        },
        .ip6 => {
            sum = checksumAdd(sum, &source);
            sum = checksumAdd(sum, &destination);
            sum += @intCast(tcp.len);
            sum += 6;
        },
    }
    return checksumFinish(checksumAdd(sum, tcp));
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

test "builds and parses an IPv4 TCP packet" {
    const key: FlowKey = .{
        .version = .ip4,
        .source = .{ 192, 0, 2, 10 } ++ ([_]u8{0} ** 12),
        .destination = .{ 198, 51, 100, 20 } ++ ([_]u8{0} ** 12),
        .source_port = 50000,
        .destination_port = 443,
    };
    var buffer: [max_mtu]u8 = undefined;
    const bytes = try build(&buffer, key, 100, 200, .{ .ack = true, .psh = true }, 32768, "hello", 1);
    const parsed = try parse(bytes);
    try std.testing.expectEqual(Version.ip4, parsed.key.version);
    try std.testing.expectEqual(key.destination_port, parsed.key.source_port);
    try std.testing.expectEqual(key.source_port, parsed.key.destination_port);
    try std.testing.expectEqual(@as(u32, 100), parsed.sequence);
    try std.testing.expectEqual(@as(u32, 200), parsed.acknowledgment);
    try std.testing.expectEqualStrings("hello", parsed.payload);
}

test "builds and parses an IPv6 SYN-ACK" {
    const key: FlowKey = .{
        .version = .ip6,
        .source = .{ 0x20, 1, 0x0d, 0xb8 } ++ ([_]u8{0} ** 12),
        .destination = .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .source_port = 40000,
        .destination_port = 80,
    };
    var buffer: [max_mtu]u8 = undefined;
    const bytes = try build(&buffer, key, 7, 12, .{ .syn = true, .ack = true }, 65535, "", 0);
    const parsed = try parse(bytes);
    try std.testing.expectEqual(Version.ip6, parsed.key.version);
    try std.testing.expect(parsed.flags.syn);
    try std.testing.expect(parsed.flags.ack);
    try std.testing.expectEqual(@as(?u16, 1440), parsed.maximum_segment_size);
    try std.testing.expectEqual(@as(usize, 0), parsed.payload.len);
}

test "IPv6 payload limit preserves a 1500-byte packet" {
    const key: FlowKey = .{
        .version = .ip6,
        .source = .{ 0x20, 1, 0x0d, 0xb8 } ++ ([_]u8{0} ** 12),
        .destination = .{ 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .source_port = 40000,
        .destination_port = 443,
    };
    var buffer: [max_mtu]u8 = undefined;
    const payload = [_]u8{0xa5} ** 1440;
    const bytes = try build(&buffer, key, 10, 20, .{ .ack = true }, 65535, &payload, 0);
    try std.testing.expectEqual(@as(usize, max_mtu), bytes.len);
    try std.testing.expectError(
        error.PacketTooLarge,
        build(&buffer, key, 10, 20, .{ .ack = true }, 65535, (&([_]u8{0} ** 1441)), 0),
    );
}

test "configured MTU controls payload size and advertised MSS" {
    const key: FlowKey = .{
        .version = .ip4,
        .source = .{ 192, 0, 2, 10 } ++ ([_]u8{0} ** 12),
        .destination = .{ 198, 51, 100, 20 } ++ ([_]u8{0} ** 12),
        .source_port = 50000,
        .destination_port = 443,
    };
    var buffer: [max_mtu]u8 = undefined;
    const syn = try buildForMtu(&buffer, key, 1, 2, .{ .syn = true, .ack = true }, 65535, &.{}, 1, 1280);
    try std.testing.expectEqual(@as(u16, 1240), std.mem.readInt(u16, syn[42..44], .big));
    try std.testing.expectEqual(@as(?u16, 1240), (try parse(syn)).maximum_segment_size);
    const payload = [_]u8{0} ** 1240;
    try std.testing.expectEqual(@as(usize, 1280), (try buildForMtu(&buffer, key, 1, 2, .{ .ack = true }, 65535, &payload, 1, 1280)).len);
    try std.testing.expectError(error.PacketTooLarge, buildForMtu(&buffer, key, 1, 2, .{ .ack = true }, 65535, &([_]u8{0} ** 1241), 1, 1280));
}

test "rejects UDP explicitly" {
    var packet = [_]u8{0} ** 20;
    packet[0] = 0x45;
    std.mem.writeInt(u16, packet[2..4], packet.len, .big);
    packet[8] = 64;
    packet[9] = 17;
    std.mem.writeInt(u16, packet[10..12], internetChecksum(&packet), .big);
    try std.testing.expectError(error.UnsupportedProtocol, parse(&packet));
}
