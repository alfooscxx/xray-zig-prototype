const std = @import("std");
const Io = std.Io;
const net = Io.net;

pub const command_udp: u8 = 0x02;
// Xray-core's MultiLengthPacketWriter uses one 8192-byte buf.Buffer for the
// two-byte length and payload.
pub const max_encoded_frame_payload = 8192 - 2;

/// Encodes the VLESS request header for classic UDP-over-stream mode. Xray's
/// `xtls-rprx-vision` flow is intentionally rejected: current Xray-core routes
/// Vision UDP through XUDP/Mux, whose wire protocol is not this length framing.
pub fn encodeRequestHeader(
    writer: *Io.Writer,
    user_id: [16]u8,
    target: net.IpAddress,
    flow: []const u8,
) !void {
    if (flow.len != 0) return error.UnsupportedVlessUdpFlow;
    try writer.writeByte(0x00);
    try writer.writeAll(&user_id);
    try writer.writeByte(0x00); // Addons length.
    try writer.writeByte(command_udp);

    var port: [2]u8 = undefined;
    std.mem.writeInt(u16, &port, target.getPort(), .big);
    try writer.writeAll(&port);
    switch (target) {
        .ip4 => |address| {
            try writer.writeByte(0x01);
            try writer.writeAll(&address.bytes);
        },
        .ip6 => |address| {
            try writer.writeByte(0x03);
            try writer.writeAll(&address.bytes);
        },
    }
}

pub fn encodeFrame(output: []u8, payload: []const u8) ![]const u8 {
    if (payload.len == 0) return error.EmptyDatagramUnsupported;
    if (payload.len > max_encoded_frame_payload or output.len < payload.len + 2) {
        return error.FrameTooLarge;
    }
    std.mem.writeInt(u16, output[0..2], @intCast(payload.len), .big);
    @memcpy(output[2 .. payload.len + 2], payload);
    return output[0 .. payload.len + 2];
}

/// Incremental decoder for a two-byte big-endian length followed by exactly
/// one UDP payload. The caller retains `output` between `push` calls and resets
/// neither it nor this decoder until `frame_len` is returned.
pub const FrameDecoder = struct {
    header: [2]u8 = undefined,
    header_len: u2 = 0,
    expected_len: ?u16 = null,
    payload_len: u16 = 0,

    pub const Result = struct {
        consumed: usize,
        frame_len: ?usize,
    };

    pub fn push(self: *FrameDecoder, input: []const u8, output: []u8) !Result {
        var consumed: usize = 0;
        while (self.header_len < 2 and consumed < input.len) {
            self.header[self.header_len] = input[consumed];
            self.header_len += 1;
            consumed += 1;
        }
        if (self.header_len < 2) return .{ .consumed = consumed, .frame_len = null };

        if (self.expected_len == null) {
            self.expected_len = std.mem.readInt(u16, &self.header, .big);
            if (self.expected_len.? > output.len) return error.FrameTooLarge;
            if (self.expected_len.? == 0) {
                self.reset();
                return .{ .consumed = consumed, .frame_len = 0 };
            }
        }

        const remaining = @as(usize, self.expected_len.?) - self.payload_len;
        const copied = @min(remaining, input.len - consumed);
        @memcpy(output[self.payload_len .. self.payload_len + copied], input[consumed .. consumed + copied]);
        self.payload_len += @intCast(copied);
        consumed += copied;
        if (self.payload_len != self.expected_len.?) {
            return .{ .consumed = consumed, .frame_len = null };
        }

        const frame_len: usize = self.payload_len;
        self.reset();
        return .{ .consumed = consumed, .frame_len = frame_len };
    }

    fn reset(self: *FrameDecoder) void {
        self.header_len = 0;
        self.expected_len = null;
        self.payload_len = 0;
    }
};

test "encodes VLESS UDP request headers for IPv4 and IPv6" {
    const user_id = [_]u8{0x11} ** 16;
    var storage: [64]u8 = undefined;
    var writer: Io.Writer = .fixed(&storage);
    try encodeRequestHeader(&writer, user_id, .{ .ip4 = .{
        .bytes = .{ 192, 0, 2, 1 },
        .port = 53,
    } }, "");
    try std.testing.expectEqualSlices(u8, &(.{
        0x00,
    } ++ ([_]u8{0x11} ** 16) ++ .{
        0x00, 0x02, 0x00, 0x35, 0x01, 192, 0, 2, 1,
    }), writer.buffered());

    var writer6: Io.Writer = .fixed(&storage);
    try encodeRequestHeader(&writer6, user_id, .{ .ip6 = .{
        .bytes = .{ 0x20, 1, 0x0d, 0xb8 } ++ ([_]u8{0} ** 12),
        .port = 5353,
        .flow = 0,
        .interface = .none,
    } }, "");
    try std.testing.expectEqual(@as(u8, 0x03), writer6.buffered()[21]);
    try std.testing.expectError(
        error.UnsupportedVlessUdpFlow,
        encodeRequestHeader(&writer6, user_id, .{ .ip4 = .loopback(53) }, "xtls-rprx-vision"),
    );
}

test "VLESS UDP frames preserve datagram boundaries under fragmentation" {
    var encoded: [64]u8 = undefined;
    const frame = try encodeFrame(&encoded, "one UDP datagram");
    var decoder: FrameDecoder = .{};
    var payload: [64]u8 = undefined;

    const a = try decoder.push(frame[0..1], &payload);
    try std.testing.expectEqual(@as(usize, 1), a.consumed);
    try std.testing.expectEqual(@as(?usize, null), a.frame_len);
    const b = try decoder.push(frame[1..5], &payload);
    try std.testing.expectEqual(@as(?usize, null), b.frame_len);
    const c = try decoder.push(frame[5..], &payload);
    try std.testing.expectEqual(@as(?usize, "one UDP datagram".len), c.frame_len);
    try std.testing.expectEqualStrings("one UDP datagram", payload[0..c.frame_len.?]);
}

test "VLESS UDP decoder preserves a coalesced following frame" {
    var first: [16]u8 = undefined;
    var second: [16]u8 = undefined;
    const a = try encodeFrame(&first, "first");
    const b = try encodeFrame(&second, "second");
    var joined: [32]u8 = undefined;
    @memcpy(joined[0..a.len], a);
    @memcpy(joined[a.len .. a.len + b.len], b);

    var decoder: FrameDecoder = .{};
    var payload: [16]u8 = undefined;
    const decoded_a = try decoder.push(joined[0 .. a.len + b.len], &payload);
    try std.testing.expectEqual(a.len, decoded_a.consumed);
    try std.testing.expectEqualStrings("first", payload[0..decoded_a.frame_len.?]);
    const decoded_b = try decoder.push(joined[decoded_a.consumed .. a.len + b.len], &payload);
    try std.testing.expectEqualStrings("second", payload[0..decoded_b.frame_len.?]);
}

test "VLESS UDP decoder rejects a frame larger than caller storage" {
    var decoder: FrameDecoder = .{};
    var payload: [4]u8 = undefined;
    try std.testing.expectError(error.FrameTooLarge, decoder.push(&.{ 0, 5 }, &payload));
}

test "VLESS UDP encoder enforces Xray buffer limits" {
    var output: [max_encoded_frame_payload + 3]u8 = undefined;
    try std.testing.expectError(error.EmptyDatagramUnsupported, encodeFrame(&output, ""));
    const oversized = [_]u8{0xaa} ** (max_encoded_frame_payload + 1);
    try std.testing.expectError(error.FrameTooLarge, encodeFrame(&output, &oversized));
}
