const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const diagnostics = @import("../../diagnostics.zig");
const log = @import("../../log.zig");
const session = @import("../../net/session.zig");
pub const vision = @import("vision.zig");

pub const Error = error{
    InvalidOutboundSettings,
    InvalidResponseVersion,
    InvalidUuid,
    InvalidTargetDomain,
    ClientEndOfStream,
    TlsRecordTooLarge,
    UpstreamEndOfStream,
};

const max_initial_tls_record_len = 18 * 1024;
const max_response_header_len = 2 + std.math.maxInt(u8);
const max_concurrent_handshakes = 32;
const initialization_timeout_seconds = 15;
var next_connection_id: std.atomic.Value(u32) = .init(1);
var handshake_slots: Io.Semaphore = .{ .permits = max_concurrent_handshakes };

pub fn handle(outbound: *const config.Outbound, client: net.Stream, sess: session.Session, preface: session.Preface, raw_reactor: *session.RawReactor, io: Io) !void {
    diagnostics.setThreadName("xz-vless-init");
    defer diagnostics.setThreadName("xray-zig");
    const connection_id = next_connection_id.fetchAdd(1, .monotonic);
    const settings = switch (outbound.settings) {
        .vless => |vless| vless,
        .none => return error.InvalidOutboundSettings,
    };
    logTarget(connection_id, sess.target);

    var upstream: session.OutboundConnection = undefined;
    connect(&upstream, outbound, settings, io) catch |err| {
        log.warn("vless {d} REALITY initialization failed: {s}\n", .{ connection_id, @errorName(err) });
        return err;
    };
    defer upstream.close(io);
    log.trace("vless {d} reality-ready\n", .{connection_id});

    var header_buffer: [4096]u8 = undefined;
    var writer: Io.Writer = .fixed(&header_buffer);

    const user_id = try parseUuid(settings.id);
    const flow = settings.flow orelse "";
    const is_vision = std.mem.eql(u8, flow, vision.flow_name);
    try encodeRequestHeader(&writer, user_id, sess.target, flow);
    try upstream.writeAll(writer.buffered(), io);

    if (is_vision) {
        var traffic_state = vision.TrafficState.init(user_id, connection_id);
        try writeInitialVisionPayload(client, &upstream, &traffic_state, preface, io);
        log.trace("vless {d} initial-ready\n", .{connection_id});
        try upstream.flush();
        diagnostics.setThreadName("xz-vless-wait");
        waitResponseHeader(client, &upstream, &traffic_state, io) catch |err| {
            log.warn("vless {d} response wait failed: {s}\n", .{ connection_id, @errorName(err) });
            return err;
        };
        log.trace("vless {d} response-ready\n", .{connection_id});
        logEstablished(connection_id, sess.target, traffic_state.is_tls);
        diagnostics.setThreadName("xz-vision-scan");
        try vision.bridge(client, &upstream, &traffic_state, sess.target, raw_reactor, io);
        log.trace("vless {d} bridge-returned\n", .{connection_id});
        return;
    }

    try upstream.writeAll(preface.bytes, io);
    try upstream.flush();
    try readResponseHeader(&upstream, io);

    try session.bridgeOutbound(client, &upstream, io);
}

fn logEstablished(connection_id: u32, target: session.Target, client_tls: bool) void {
    switch (target) {
        .address => |address| log.info(
            "vless {d} established target={f} client_tls={}\n",
            .{ connection_id, address, client_tls },
        ),
        .host => |host| log.info(
            "vless {d} established target={s}:{d} client_tls={}\n",
            .{ connection_id, host.name.bytes, host.port, client_tls },
        ),
    }
}

const ResponseHeaderState = struct {
    bytes: [max_response_header_len]u8 = undefined,
    len: usize = 0,
    expected_len: usize = 2,
    fixed_parsed: bool = false,

    fn writable(self: *ResponseHeaderState) []u8 {
        return self.bytes[self.len..self.expected_len];
    }

    fn advance(self: *ResponseHeaderState, len: usize) !bool {
        std.debug.assert(len <= self.expected_len - self.len);
        self.len += len;
        if (self.len < self.expected_len) return false;

        if (!self.fixed_parsed) {
            if (self.bytes[0] != 0x00) return error.InvalidResponseVersion;
            self.fixed_parsed = true;
            self.expected_len += self.bytes[1];
        }
        return self.len == self.expected_len;
    }
};

fn waitResponseHeader(
    client: net.Stream,
    upstream: *session.OutboundConnection,
    traffic_state: *vision.TrafficState,
    io: Io,
) !void {
    var client_read_buffer: [16 * 1024]u8 = undefined;
    var client_reader = client.reader(io, &client_read_buffer);
    var client_chunk: [16 * 1024]u8 = undefined;
    var response: ResponseHeaderState = .{};

    while (true) {
        const ready: session.Readable = if (client_reader.interface.buffered().len != 0 or
            upstream.hasBufferedRead())
            .{
                .first = client_reader.interface.buffered().len != 0,
                .second = upstream.hasBufferedRead(),
            }
        else
            try session.waitReadableTimeout(
                client,
                upstream.pollStream(),
                session.response_header_timeout_ms,
            );

        if (ready.first) {
            const n = try session.readAvailable(&client_reader.interface, &client_chunk);
            if (n == 0) return error.ClientEndOfStream;
            try vision.writeUplink(upstream, traffic_state, client_chunk[0..n], io);
            try upstream.flush();
            log.trace("vless {d} response-wait uplink={d}\n", .{ traffic_state.connection_id, n });
        }

        if (ready.second) {
            while (true) {
                const n = upstream.read(response.writable(), io) catch |err| switch (err) {
                    error.ReadPending => break,
                    else => |e| return e,
                };
                if (n == 0) return error.UpstreamEndOfStream;
                if (try response.advance(n)) return;
            }
        }
    }
}

fn logTarget(connection_id: u32, target: session.Target) void {
    switch (target) {
        .address => |address| log.debug("vless {d} target={f}\n", .{ connection_id, address }),
        .host => |host| log.debug("vless {d} target={s}:{d}\n", .{ connection_id, host.name.bytes, host.port }),
    }
}

fn writeInitialVisionPayload(
    client: net.Stream,
    upstream: *session.OutboundConnection,
    traffic_state: *vision.TrafficState,
    preface: session.Preface,
    io: Io,
) !void {
    if (preface.bytes.len != 0) {
        try vision.writeUplink(upstream, traffic_state, preface.bytes, io);
        return;
    }

    var chunk: [max_initial_tls_record_len]u8 = undefined;
    var used: usize = 0;
    var expected_len: usize = 5;
    while (used < expected_len) {
        const message = client.socket.receiveTimeout(io, chunk[used..expected_len], .{
            .duration = .{
                .raw = Io.Duration.fromMilliseconds(500),
                .clock = .awake,
            },
        }) catch |err| switch (err) {
            error.Timeout => {
                if (used == 0) {
                    try vision.writeUplink(upstream, traffic_state, &.{}, io);
                    return;
                }
                break;
            },
            else => |e| return e,
        };
        if (message.data.len == 0) break;
        used += message.data.len;

        const record_len = try expectedInitialTlsRecordLen(chunk[0..used]) orelse break;
        if (used == 5) expected_len = record_len;
    }

    try vision.writeUplink(upstream, traffic_state, chunk[0..used], io);
}

fn expectedInitialTlsRecordLen(bytes: []const u8) !?usize {
    if (bytes.len == 0) return null;
    if (bytes[0] < 0x14 or bytes[0] > 0x17) return null;
    if (bytes.len >= 2 and bytes[1] != 0x03) return null;
    if (bytes.len < 5) return 5;

    const payload_len = std.mem.readInt(u16, bytes[3..5], .big);
    const record_len = 5 + @as(usize, payload_len);
    if (record_len > max_initial_tls_record_len) return error.TlsRecordTooLarge;
    return record_len;
}

fn connect(upstream: *session.OutboundConnection, outbound: *const config.Outbound, settings: config.VlessOutboundSettings, io: Io) !void {
    try handshake_slots.wait(io);
    defer handshake_slots.post(io);

    const deadline = Io.Clock.Timestamp.fromNow(io, .{
        .raw = Io.Duration.fromSeconds(initialization_timeout_seconds),
        .clock = .awake,
    });
    const tcp = try session.connectHostOrIpTimeout(
        settings.address,
        settings.port,
        io,
        .{ .deadline = deadline },
    );
    errdefer tcp.close(io);

    if (outbound.stream.security) |security| {
        if (std.mem.eql(u8, security, "reality")) {
            try upstream.initReality(tcp, outbound.stream.reality.?, io, deadline);
            return;
        }
    }

    upstream.initPlain(tcp);
}

fn readResponseHeader(upstream: *session.OutboundConnection, io: Io) !void {
    var fixed: [2]u8 = undefined;
    try upstream.readSliceAll(&fixed, io);
    if (fixed[0] != 0x00) return error.InvalidResponseVersion;

    const addons_len = fixed[1];
    if (addons_len == 0) return;

    var discard: [255]u8 = undefined;
    try upstream.readSliceAll(discard[0..addons_len], io);
}

pub fn encodeRequestHeader(writer: *Io.Writer, user_id: [16]u8, target: session.Target, flow: []const u8) !void {
    try writer.writeByte(0x00);
    try writer.writeAll(&user_id);
    try encodeHeaderAddons(writer, flow);
    try writer.writeByte(0x01);
    try writePortThenAddress(writer, target);
}

pub fn encodeHeaderAddons(writer: *Io.Writer, flow: []const u8) !void {
    if (flow.len == 0) {
        try writer.writeByte(0x00);
        return;
    }

    if (!std.mem.eql(u8, flow, vision.flow_name)) return error.UnsupportedVlessFlow;
    if (flow.len > 255 - 2) return error.UnsupportedVlessFlow;

    try writer.writeByte(@intCast(flow.len + 2));
    try writer.writeByte(0x0a);
    try writer.writeByte(@intCast(flow.len));
    try writer.writeAll(flow);
}

fn writePortThenAddress(writer: *Io.Writer, target: session.Target) !void {
    var port_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &port_bytes, target.port(), .big);
    try writer.writeAll(&port_bytes);

    switch (target) {
        .address => |address| switch (address) {
            .ip4 => |ip4| {
                try writer.writeByte(0x01);
                try writer.writeAll(&ip4.bytes);
            },
            .ip6 => |ip6| {
                try writer.writeByte(0x03);
                try writer.writeAll(&ip6.bytes);
            },
        },
        .host => |host| {
            if (host.name.bytes.len > 255) return error.InvalidTargetDomain;
            try writer.writeByte(0x02);
            try writer.writeByte(@intCast(host.name.bytes.len));
            try writer.writeAll(host.name.bytes);
        },
    }
}

pub fn parseUuid(text: []const u8) ![16]u8 {
    if (text.len != 36) return error.InvalidUuid;
    if (text[8] != '-' or text[13] != '-' or text[18] != '-' or text[23] != '-') {
        return error.InvalidUuid;
    }

    var out: [16]u8 = undefined;
    var out_i: usize = 0;
    var text_i: usize = 0;
    while (text_i < text.len) {
        if (text[text_i] == '-') {
            text_i += 1;
            continue;
        }
        if (out_i >= out.len) return error.InvalidUuid;
        const hi = hexValue(text[text_i]) orelse return error.InvalidUuid;
        const lo = hexValue(text[text_i + 1]) orelse return error.InvalidUuid;
        out[out_i] = (hi << 4) | lo;
        out_i += 1;
        text_i += 2;
    }
    if (out_i != out.len) return error.InvalidUuid;
    return out;
}

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

test "parses UUID" {
    const uuid = try parseUuid("00112233-4455-6677-8899-aabbccddeeff");
    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    }, &uuid);
}

test "parses fragmented VLESS response header" {
    var response: ResponseHeaderState = .{};

    response.writable()[0] = 0x00;
    try std.testing.expect(!try response.advance(1));
    response.writable()[0] = 0x02;
    try std.testing.expect(!try response.advance(1));
    try std.testing.expectEqual(@as(usize, 2), response.writable().len);

    response.writable()[0..2].* = .{ 0xaa, 0xbb };
    try std.testing.expect(try response.advance(2));
}

test "rejects invalid VLESS response version" {
    var response: ResponseHeaderState = .{};
    response.writable()[0..2].* = .{ 0x01, 0x00 };
    try std.testing.expectError(error.InvalidResponseVersion, response.advance(2));
}

test "encodes VLESS TCP request header for domain target" {
    const uuid = try parseUuid("00112233-4455-6677-8899-aabbccddeeff");
    const target = try session.targetFromHostBytes("example.com", 443);

    var out: [128]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    try encodeRequestHeader(&writer, uuid, target, "");

    const actual = writer.buffered();
    try std.testing.expectEqualSlices(u8, &.{
        0x00,
        0x00,
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x99,
        0xaa,
        0xbb,
        0xcc,
        0xdd,
        0xee,
        0xff,
        0x00,
        0x01,
        0x01,
        0xbb,
        0x02,
        0x0b,
        'e',
        'x',
        'a',
        'm',
        'p',
        'l',
        'e',
        '.',
        'c',
        'o',
        'm',
    }, actual);
}

test "waits for a complete initial TLS record" {
    try std.testing.expectEqual(@as(?usize, 5), try expectedInitialTlsRecordLen(&.{ 0x16, 0x03 }));
    try std.testing.expectEqual(@as(?usize, 9), try expectedInitialTlsRecordLen(&.{ 0x16, 0x03, 0x01, 0x00, 0x04 }));
    try std.testing.expectEqual(@as(?usize, 9), try expectedInitialTlsRecordLen(&.{
        0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00,
    }));
    try std.testing.expectEqual(@as(?usize, null), try expectedInitialTlsRecordLen("GET /"));
}

test "rejects oversized initial TLS records" {
    try std.testing.expectError(error.TlsRecordTooLarge, expectedInitialTlsRecordLen(&.{
        0x16, 0x03, 0x01, 0xff, 0xff,
    }));
}

test "encodes VLESS Vision header addon protobuf" {
    var out: [32]u8 = undefined;
    var writer: Io.Writer = .fixed(&out);
    try encodeHeaderAddons(&writer, vision.flow_name);

    try std.testing.expectEqualSlices(u8, &.{
        0x12,
        0x0a,
        0x10,
        'x',
        't',
        'l',
        's',
        '-',
        'r',
        'p',
        'r',
        'x',
        '-',
        'v',
        'i',
        's',
        'i',
        'o',
        'n',
    }, writer.buffered());
}
