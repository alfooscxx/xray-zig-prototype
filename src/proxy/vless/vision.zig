const std = @import("std");
const Io = std.Io;
const net = Io.net;

const session = @import("../../net/session.zig");
const log = @import("../../log.zig");

pub const flow_name = "xtls-rprx-vision";

const max_buffer_size = 8192;
const frame_header_len = 5;
const first_frame_overhead = 16 + frame_header_len;
const max_content_len = max_buffer_size - first_frame_overhead;
const max_tls_record_len = 18 * 1024;
const max_server_hello_len = 1024;

const tls13_supported_versions = [_]u8{ 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04 };
const tls_client_handshake_start = [_]u8{ 0x16, 0x03 };
const tls_server_handshake_start = [_]u8{ 0x16, 0x03, 0x03 };
const tls_application_data_start = [_]u8{ 0x17, 0x03, 0x03 };
const tls_handshake_type_client_hello = 0x01;
const tls_handshake_type_server_hello = 0x02;

pub const Command = enum(u8) {
    continue_padding = 0x00,
    end = 0x01,
    direct = 0x02,
};

pub const Direction = enum {
    uplink,
    downlink,
};

const LinkState = struct {
    initial_frame: [first_frame_overhead]u8 = undefined,
    initial_frame_len: usize = 0,
    within_padding_buffers: bool = true,
    reader_direct_copy: bool = false,
    remaining_command: i32 = -1,
    remaining_content: i32 = -1,
    remaining_padding: i32 = -1,
    current_command: u8 = 0,
    writer_is_padding: bool = true,
    writer_direct_copy: bool = false,
    writer_sent_user_uuid: bool = false,
};

pub const TrafficState = struct {
    user_uuid: [16]u8,
    connection_id: u32,
    number_of_packets_to_filter: i32 = 8,
    enable_xtls: bool = false,
    is_tls12_or_above: bool = false,
    is_tls: bool = false,
    cipher: u16 = 0,
    server_hello_probe: [max_server_hello_len]u8 = undefined,
    server_hello_probe_len: usize = 0,
    inbound: LinkState = .{},
    outbound: LinkState = .{},
    first_raw_uplink_logged: bool = false,

    pub fn init(user_uuid: [16]u8, connection_id: u32) TrafficState {
        return .{ .user_uuid = user_uuid, .connection_id = connection_id };
    }
};

pub fn bridge(client: net.Stream, upstream: *session.OutboundConnection, state: *TrafficState, raw_reactor: *session.RawReactor, io: Io) Io.Cancelable!void {
    var client_read_buffer: [16 * 1024]u8 = undefined;
    var client_reader = client.reader(io, &client_read_buffer);
    var client_write_buffer: [16 * 1024]u8 = undefined;
    var client_writer = client.writer(io, &client_write_buffer);

    var uplink_chunk: [max_tls_record_len]u8 = undefined;
    var uplink_pending: usize = 0;
    var downlink_chunk: [16 * 1024]u8 = undefined;
    var decoded: [16 * 1024 + first_frame_overhead]u8 = undefined;

    while (true) {
        if (state.outbound.writer_direct_copy and state.outbound.reader_direct_copy and
            uplink_pending == 0 and client_reader.interface.buffered().len == 0 and
            upstream.rawHandoffReady())
        {
            upstream.flush() catch return;
            raw_reactor.adoptDuplicate(client, upstream.pollStream()) catch return;
            log.trace("vision {d} raw handoff\n", .{state.connection_id});
            return;
        }
        const ready: session.Readable = if (client_reader.interface.buffered().len != 0 or
            upstream.hasBufferedRead())
            .{
                .first = client_reader.interface.buffered().len != 0,
                .second = upstream.hasBufferedRead(),
            }
        else
            session.waitReadable(client, upstream.pollStream()) catch return;
        if (ready.first and !forwardUplinkOnce(
            &client_reader.interface,
            upstream,
            state,
            io,
            &uplink_chunk,
            &uplink_pending,
        )) {
            logBridgeExit("uplink", state);
            return;
        }
        if (ready.second and !forwardDownlinkOnce(
            upstream,
            &client_writer.interface,
            state,
            io,
            &downlink_chunk,
            &decoded,
        )) {
            logBridgeExit("downlink", state);
            return;
        }
    }
}

fn logBridgeExit(reason: []const u8, state: *const TrafficState) void {
    log.trace(
        "vision {d} exit {s} tls={} tls12={} xtls={} write_direct={} read_direct={} cipher=0x{x} filter={d}\n",
        .{
            state.connection_id,
            reason,
            state.is_tls,
            state.is_tls12_or_above,
            state.enable_xtls,
            state.outbound.writer_direct_copy,
            state.outbound.reader_direct_copy,
            state.cipher,
            state.number_of_packets_to_filter,
        },
    );
}

pub fn writeUplink(destination: *session.OutboundConnection, state: *TrafficState, bytes: []const u8, io: Io) !void {
    try writeVision(.uplink, destination, state, bytes, io);
}

fn isTlsRecordPrefix(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    if (bytes[0] < 0x14 or bytes[0] > 0x17) return false;
    return bytes.len < 2 or bytes[1] == 0x03;
}

fn tlsRecordLen(header: []const u8) !usize {
    std.debug.assert(header.len >= 5);
    const payload_len = std.mem.readInt(u16, header[3..5], .big);
    const record_len = 5 + @as(usize, payload_len);
    if (record_len > max_tls_record_len) return error.TlsRecordTooLarge;
    return record_len;
}

fn forwardUplinkOnce(
    reader: *Io.Reader,
    destination: *session.OutboundConnection,
    state: *TrafficState,
    io: Io,
    chunk: *[max_tls_record_len]u8,
    pending_len: *usize,
) bool {
    const tls_stream = state.is_tls;

    if (state.outbound.writer_direct_copy or !tls_stream) {
        const n = session.readAvailable(reader, chunk) catch return false;
        if (n == 0) return false;
        const was_direct = state.outbound.writer_direct_copy;
        writeUplink(destination, state, chunk[0..n], io) catch return false;
        destination.flush() catch return false;
        if (!was_direct and state.outbound.writer_direct_copy) {
            log.trace("vision {d} uplink direct frame flushed\n", .{state.connection_id});
        }
        return true;
    }

    const target_len = if (pending_len.* < 5)
        @as(usize, 5)
    else
        tlsRecordLen(chunk[0..5]) catch return false;
    const n = session.readAvailable(reader, chunk[pending_len.*..target_len]) catch return false;
    if (n == 0) return false;
    pending_len.* += n;
    if (pending_len.* < target_len) return true;
    if (pending_len.* == 5 and !isTlsRecordPrefix(chunk[0..5])) return false;

    const record_len = tlsRecordLen(chunk[0..5]) catch return false;
    if (pending_len.* < record_len) return true;

    const was_direct = state.outbound.writer_direct_copy;
    writeUplink(destination, state, chunk[0..pending_len.*], io) catch return false;
    destination.flush() catch return false;
    if (!was_direct and state.outbound.writer_direct_copy) {
        log.trace("vision {d} uplink direct frame flushed\n", .{state.connection_id});
    }
    pending_len.* = 0;
    return true;
}

fn forwardDownlinkOnce(
    source: *session.OutboundConnection,
    writer: *Io.Writer,
    state: *TrafficState,
    io: Io,
    chunk: *[16 * 1024]u8,
    decoded: *[16 * 1024 + first_frame_overhead]u8,
) bool {
    const n = source.read(chunk, io) catch |err| switch (err) {
        error.ReadPending => return true,
        else => return false,
    };
    if (n == 0) return false;

    var decoded_writer: Io.Writer = .fixed(decoded);
    decodeChunk(state, .downlink, chunk[0..n], &decoded_writer) catch return false;
    const cleartext = decoded_writer.buffered();
    log.trace(
        "vision {d} downlink chunk outer_clear={d} decoded={d} read_direct={}\n",
        .{ state.connection_id, n, cleartext.len, state.outbound.reader_direct_copy },
    );
    if (state.outbound.reader_direct_copy) {
        source.enableDirectRead();
    }
    if (cleartext.len == 0) return true;
    if (state.number_of_packets_to_filter > 0) {
        filterServerTls(state, cleartext);
    }
    writer.writeAll(cleartext) catch return false;
    writer.flush() catch return false;
    return true;
}

fn writeVision(direction: Direction, destination: *session.OutboundConnection, state: *TrafficState, bytes: []const u8, io: Io) !void {
    const link = writerState(state, direction);
    if (link.writer_direct_copy) {
        destination.enableDirectWrite();
        try destination.writeAll(bytes, io);
        if (direction == .uplink and !state.first_raw_uplink_logged) {
            state.first_raw_uplink_logged = true;
            log.trace("vision {d} first raw uplink bytes={d}\n", .{ state.connection_id, bytes.len });
        }
        return;
    }

    if (bytes.len != 0 and state.number_of_packets_to_filter > 0) {
        filterClientTls(state, bytes);
    }

    if (!link.writer_is_padding) {
        try destination.writeAll(bytes, io);
        return;
    }

    if (bytes.len == 0) {
        try writeFrameToOutbound(destination, state, link, .continue_padding, bytes, true, io);
        return;
    }

    const complete_tls_record = isCompleteTlsApplicationData(bytes);
    var long_padding = state.is_tls;
    var direct_after_write = false;
    var offset: usize = 0;

    while (offset < bytes.len) {
        const part_len = @min(max_content_len, bytes.len - offset);
        const part = bytes[offset..][0..part_len];
        offset += part_len;
        const is_last = offset == bytes.len;

        var command: Command = .continue_padding;
        var frame_long_padding = long_padding;
        var end_padding_now = false;
        var raw_tail = false;

        if (state.is_tls and part.len >= 6 and std.mem.startsWith(u8, part, &tls_application_data_start) and complete_tls_record) {
            if (state.enable_xtls) direct_after_write = true;
            if (is_last) {
                command = if (state.enable_xtls) .direct else .end;
            }
            link.writer_is_padding = false;
            frame_long_padding = true;
            long_padding = false;
        } else if (!state.is_tls12_or_above and state.number_of_packets_to_filter <= 1) {
            command = .end;
            link.writer_is_padding = false;
            end_padding_now = true;
            raw_tail = !is_last;
        } else if (is_last and !link.writer_is_padding) {
            command = if (state.enable_xtls) .direct else .end;
            if (state.enable_xtls) direct_after_write = true;
        }

        try writeFrameToOutbound(destination, state, link, command, part, frame_long_padding, io);
        if (end_padding_now and raw_tail) {
            try destination.writeAll(bytes[offset..], io);
            break;
        }
    }

    if (direct_after_write) {
        link.writer_direct_copy = true;
    }
}

fn writeFrameToOutbound(
    destination: *session.OutboundConnection,
    state: *TrafficState,
    link: *LinkState,
    command: Command,
    content: []const u8,
    long_padding: bool,
    io: Io,
) !void {
    var frame: [max_buffer_size]u8 = undefined;
    var writer: Io.Writer = .fixed(&frame);
    const user_uuid: ?[16]u8 = if (link.writer_sent_user_uuid) null else state.user_uuid;
    link.writer_sent_user_uuid = true;
    const padding_len = randomPaddingLen(content.len, long_padding, io);
    try encodeFrame(&writer, user_uuid, command, content, padding_len);
    try destination.writeAll(writer.buffered(), io);
    log.trace(
        "vision {d} {s} frame command={s} content={d} padding={d} outer_bytes={d}\n",
        .{
            state.connection_id,
            @tagName(if (link == &state.outbound) Direction.uplink else Direction.downlink),
            @tagName(command),
            content.len,
            padding_len,
            writer.buffered().len,
        },
    );
}

pub fn encodeFrame(
    writer: *Io.Writer,
    user_uuid: ?[16]u8,
    command: Command,
    content: []const u8,
    padding_len: usize,
) !void {
    if (content.len > std.math.maxInt(u16) or padding_len > std.math.maxInt(u16)) {
        return error.VisionFrameTooLarge;
    }
    if (user_uuid) |uuid| {
        try writer.writeAll(&uuid);
    }
    try writer.writeByte(@intFromEnum(command));

    var len_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_bytes, @intCast(content.len), .big);
    try writer.writeAll(&len_bytes);
    std.mem.writeInt(u16, &len_bytes, @intCast(padding_len), .big);
    try writer.writeAll(&len_bytes);

    try writer.writeAll(content);
    try writer.splatByteAll(0, padding_len);
}

fn randomPaddingLen(content_len: usize, long_padding: bool, io: Io) usize {
    var padding_len: usize = if (long_padding and content_len < 900)
        @as(usize, randomBelow(500, io)) + 900 - content_len
    else
        @as(usize, randomBelow(256, io));

    const max_padding = max_content_len - @min(content_len, max_content_len);
    if (padding_len > max_padding) padding_len = max_padding;
    return padding_len;
}

fn randomBelow(comptime limit: u16, io: Io) u16 {
    var bytes: [2]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u16, &bytes, .big) % limit;
}

pub fn decodeChunk(state: *TrafficState, direction: Direction, input: []const u8, writer: *Io.Writer) !void {
    const link = readerState(state, direction);
    if (link.reader_direct_copy or (!link.within_padding_buffers and state.number_of_packets_to_filter <= 0)) {
        try writer.writeAll(input);
        return;
    }

    var index: usize = 0;
    if (link.remaining_command == -1 and link.remaining_content == -1 and link.remaining_padding == -1) {
        const take = @min(first_frame_overhead - link.initial_frame_len, input.len);
        @memcpy(link.initial_frame[link.initial_frame_len..][0..take], input[0..take]);
        link.initial_frame_len += take;
        index = take;
        if (link.initial_frame_len < first_frame_overhead) return;

        if (!std.mem.eql(u8, link.initial_frame[0..16], &state.user_uuid)) {
            try writer.writeAll(&link.initial_frame);
            try writer.writeAll(input[index..]);
            link.initial_frame_len = 0;
            finishReaderChunk(state, link);
            return;
        }

        link.current_command = link.initial_frame[16];
        link.remaining_content = std.mem.readInt(u16, link.initial_frame[17..19], .big);
        link.remaining_padding = std.mem.readInt(u16, link.initial_frame[19..21], .big);
        link.remaining_command = 0;
        link.initial_frame_len = 0;
        log.trace(
            "vision {d} {s} initial frame command={d} content={d} padding={d}\n",
            .{
                state.connection_id,
                @tagName(direction),
                link.current_command,
                link.remaining_content,
                link.remaining_padding,
            },
        );

        if (link.remaining_content == 0 and link.remaining_padding == 0) {
            if (link.current_command == @intFromEnum(Command.continue_padding)) {
                link.remaining_command = frame_header_len;
            } else {
                link.remaining_command = -1;
                link.remaining_content = -1;
                link.remaining_padding = -1;
                if (index < input.len) try writer.writeAll(input[index..]);
                finishReaderChunk(state, link);
                return;
            }
        }
    }

    while (index < input.len) {
        if (link.remaining_command > 0) {
            const data = input[index];
            index += 1;
            switch (link.remaining_command) {
                5 => link.current_command = data,
                4 => link.remaining_content = @as(i32, data) << 8,
                3 => link.remaining_content |= data,
                2 => link.remaining_padding = @as(i32, data) << 8,
                1 => link.remaining_padding |= data,
                else => unreachable,
            }
            link.remaining_command -= 1;
            if (link.remaining_command == 0) {
                log.trace(
                    "vision {d} {s} frame command={d} content={d} padding={d}\n",
                    .{
                        state.connection_id,
                        @tagName(direction),
                        link.current_command,
                        link.remaining_content,
                        link.remaining_padding,
                    },
                );
            }
        } else if (link.remaining_content > 0) {
            const take = @min(@as(usize, @intCast(link.remaining_content)), input.len - index);
            try writer.writeAll(input[index..][0..take]);
            index += take;
            link.remaining_content -= @intCast(take);
        } else if (link.remaining_padding > 0) {
            const take = @min(@as(usize, @intCast(link.remaining_padding)), input.len - index);
            index += take;
            link.remaining_padding -= @intCast(take);
        }

        if (link.remaining_command <= 0 and link.remaining_content <= 0 and link.remaining_padding <= 0) {
            if (link.current_command == @intFromEnum(Command.continue_padding)) {
                link.remaining_command = frame_header_len;
            } else {
                link.remaining_command = -1;
                link.remaining_content = -1;
                link.remaining_padding = -1;
                if (index < input.len) {
                    try writer.writeAll(input[index..]);
                }
                break;
            }
        }
    }

    finishReaderChunk(state, link);
}

fn finishReaderChunk(state: *TrafficState, link: *LinkState) void {
    _ = state;
    if (link.remaining_content > 0 or link.remaining_padding > 0 or link.current_command == @intFromEnum(Command.continue_padding)) {
        link.within_padding_buffers = true;
    } else if (link.current_command == @intFromEnum(Command.end)) {
        link.within_padding_buffers = false;
    } else if (link.current_command == @intFromEnum(Command.direct)) {
        link.within_padding_buffers = false;
        link.reader_direct_copy = true;
    }
}

fn writerState(state: *TrafficState, direction: Direction) *LinkState {
    return switch (direction) {
        .uplink => &state.outbound,
        .downlink => &state.inbound,
    };
}

fn readerState(state: *TrafficState, direction: Direction) *LinkState {
    return switch (direction) {
        .uplink => &state.inbound,
        .downlink => &state.outbound,
    };
}

fn filterClientTls(state: *TrafficState, bytes: []const u8) void {
    if (state.number_of_packets_to_filter <= 0) return;
    state.number_of_packets_to_filter -= 1;

    if (bytes.len >= 6 and std.mem.startsWith(u8, bytes, &tls_client_handshake_start) and
        bytes[5] == tls_handshake_type_client_hello)
    {
        state.is_tls = true;
    }
}

fn filterServerTls(state: *TrafficState, bytes: []const u8) void {
    if (state.number_of_packets_to_filter <= 0 or state.enable_xtls) return;

    const available = max_server_hello_len - state.server_hello_probe_len;
    const take = @min(available, bytes.len);
    @memcpy(state.server_hello_probe[state.server_hello_probe_len..][0..take], bytes[0..take]);
    state.server_hello_probe_len += take;

    const probe = state.server_hello_probe[0..state.server_hello_probe_len];
    const prefix_len = @min(probe.len, tls_server_handshake_start.len);
    if (!std.mem.eql(u8, probe[0..prefix_len], tls_server_handshake_start[0..prefix_len])) {
        state.number_of_packets_to_filter -= 1;
        state.server_hello_probe_len = 0;
        return;
    }
    if (probe.len < 9) return;
    if (probe[5] != tls_handshake_type_server_hello) {
        state.number_of_packets_to_filter -= 1;
        state.server_hello_probe_len = 0;
        return;
    }

    const handshake_len = (@as(usize, probe[6]) << 16) |
        (@as(usize, probe[7]) << 8) | probe[8];
    const total_len = 9 + handshake_len;
    if (total_len > max_server_hello_len) {
        state.number_of_packets_to_filter = 0;
        return;
    }
    if (probe.len < total_len) return;

    state.is_tls12_or_above = true;
    state.is_tls = true;
    if (total_len > 46) {
        const session_id_len: usize = probe[43];
        const cipher_index = 44 + session_id_len;
        if (cipher_index + 2 <= total_len) {
            state.cipher = std.mem.readInt(u16, probe[cipher_index..][0..2], .big);
        }
    }

    state.enable_xtls = std.mem.indexOf(u8, probe[0..total_len], &tls13_supported_versions) != null and
        tls13CipherCanUseDirectCopy(state.cipher);
    state.number_of_packets_to_filter = 0;
}

fn tls13CipherCanUseDirectCopy(cipher: u16) bool {
    return switch (cipher) {
        0x1301, 0x1302, 0x1303, 0x1304 => true,
        else => false,
    };
}

pub fn isCompleteTlsApplicationData(bytes: []const u8) bool {
    var header_len: usize = 5;
    var record_len: usize = 0;
    var index: usize = 0;

    while (index < bytes.len) {
        if (header_len > 0) {
            const data = bytes[index];
            index += 1;
            switch (header_len) {
                5 => if (data != 0x17) return false,
                4 => if (data != 0x03) return false,
                3 => if (data != 0x03) return false,
                2 => record_len = @as(usize, data) << 8,
                1 => record_len |= data,
                else => unreachable,
            }
            header_len -= 1;
        } else if (record_len > 0) {
            const remaining = bytes.len - index;
            if (remaining < record_len) return false;
            index += record_len;
            record_len = 0;
            header_len = 5;
        } else {
            return false;
        }
    }

    return header_len == 5 and record_len == 0;
}

test "encodes and decodes fixed Vision padding block" {
    const uuid = [_]u8{
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    };

    var frame: [64]u8 = undefined;
    var frame_writer: Io.Writer = .fixed(&frame);
    try encodeFrame(&frame_writer, uuid, .end, "ping", 3);

    try std.testing.expectEqualSlices(u8, &.{
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
        0x01, 0x00, 0x04, 0x00,
        0x03, 'p',  'i',  'n',
        'g',  0x00, 0x00, 0x00,
    }, frame_writer.buffered());

    var state = TrafficState.init(uuid, 1);
    var decoded: [16]u8 = undefined;
    var decoded_writer: Io.Writer = .fixed(&decoded);
    try decodeChunk(&state, .downlink, frame_writer.buffered(), &decoded_writer);

    try std.testing.expectEqualSlices(u8, "ping", decoded_writer.buffered());
    try std.testing.expect(!state.outbound.within_padding_buffers);
    try std.testing.expect(!state.outbound.reader_direct_copy);
}

test "detects TLS ClientHello" {
    var state = TrafficState.init([_]u8{0} ** 16, 1);
    filterClientTls(&state, &.{
        0x16, 0x03, 0x01, 0x00, 0x2a, 0x01,
        0x00, 0x00, 0x26,
    });
    try std.testing.expect(state.is_tls);
    try std.testing.expect(!state.is_tls12_or_above);
    try std.testing.expectEqual(@as(i32, 7), state.number_of_packets_to_filter);
}

test "detects TLS 1.3 ServerHello and direct command transition" {
    const uuid = [_]u8{
        0xaa, 0xbb, 0xcc, 0xdd,
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xee, 0xff,
    };
    var state = TrafficState.init(uuid, 1);

    var server_hello = [_]u8{0} ** 96;
    server_hello[0..9].* = .{ 0x16, 0x03, 0x03, 0x00, 0x5b, 0x02, 0x00, 0x00, 0x57 };
    server_hello[43] = 0;
    server_hello[44] = 0x13;
    server_hello[45] = 0x01;
    server_hello[70..76].* = tls13_supported_versions;
    filterServerTls(&state, &server_hello);

    try std.testing.expect(state.is_tls);
    try std.testing.expect(state.is_tls12_or_above);
    try std.testing.expect(state.enable_xtls);
    try std.testing.expectEqual(@as(i32, 0), state.number_of_packets_to_filter);

    var frame: [64]u8 = undefined;
    var frame_writer: Io.Writer = .fixed(&frame);
    try encodeFrame(&frame_writer, uuid, .direct, "abc", 2);

    var decoded: [16]u8 = undefined;
    var decoded_writer: Io.Writer = .fixed(&decoded);
    try decodeChunk(&state, .downlink, frame_writer.buffered(), &decoded_writer);

    try std.testing.expectEqualSlices(u8, "abc", decoded_writer.buffered());
    try std.testing.expect(state.outbound.reader_direct_copy);
    try std.testing.expect(!state.outbound.within_padding_buffers);
}

test "assembles fragmented TLS 1.3 ServerHello" {
    var state = TrafficState.init([_]u8{0} ** 16, 1);
    var server_hello = [_]u8{0} ** 96;
    server_hello[0..9].* = .{ 0x16, 0x03, 0x03, 0x00, 0x5b, 0x02, 0x00, 0x00, 0x57 };
    server_hello[43] = 0;
    server_hello[44] = 0x13;
    server_hello[45] = 0x03;
    server_hello[70..76].* = tls13_supported_versions;

    for (server_hello) |byte| filterServerTls(&state, &.{byte});

    try std.testing.expect(state.is_tls12_or_above);
    try std.testing.expect(state.enable_xtls);
    try std.testing.expectEqual(@as(u16, 0x1303), state.cipher);
}

test "assembles split initial Vision frame before decoding" {
    const uuid = [_]u8{
        0xaa, 0xbb, 0xcc, 0xdd,
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xee, 0xff,
    };
    var state = TrafficState.init(uuid, 1);
    state.enable_xtls = true;

    var frame: [64]u8 = undefined;
    var frame_writer: Io.Writer = .fixed(&frame);
    try encodeFrame(&frame_writer, uuid, .direct, "response", 3);

    var decoded: [32]u8 = undefined;
    var decoded_writer: Io.Writer = .fixed(&decoded);
    for (frame_writer.buffered()) |byte| {
        try decodeChunk(&state, .downlink, &.{byte}, &decoded_writer);
    }

    try std.testing.expectEqualSlices(u8, "response", decoded_writer.buffered());
    try std.testing.expect(state.outbound.reader_direct_copy);
}

test "recognizes complete TLS application data records" {
    try std.testing.expect(isCompleteTlsApplicationData(&.{
        0x17, 0x03, 0x03, 0x00, 0x02, 0xaa, 0xbb,
        0x17, 0x03, 0x03, 0x00, 0x01, 0xcc,
    }));
    try std.testing.expect(!isCompleteTlsApplicationData(&.{
        0x17, 0x03, 0x03, 0x00, 0x02, 0xaa,
    }));
}

test "recognizes partial TLS record prefixes and lengths" {
    try std.testing.expect(isTlsRecordPrefix(&.{0x16}));
    try std.testing.expect(isTlsRecordPrefix(&.{ 0x16, 0x03 }));
    try std.testing.expect(!isTlsRecordPrefix(&.{ 0x16, 0x02 }));
    try std.testing.expect(!isTlsRecordPrefix("GET /"));
    try std.testing.expectEqual(@as(usize, 9), try tlsRecordLen(&.{ 0x16, 0x03, 0x01, 0x00, 0x04 }));
}
