const std = @import("std");
const Io = std.Io;
const net = Io.net;

const xray = @import("xray_zig");
const dns = xray.dns.protocol;

const dns_port = 15353;
const echo_port = 18080;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    var threaded: Io.Threaded = .init(init.gpa, .{ .stack_size = 256 * 1024, .concurrent_limit = .limited(32) });
    defer threaded.deinit();
    const io = threaded.io();

    if (args.len == 2 and std.mem.eql(u8, args[1], "server")) return runServer(io);
    if (args.len == 2 and std.mem.eql(u8, args[1], "server-literals")) return runLiteralServer(io);
    if (args.len == 4 and std.mem.eql(u8, args[1], "expect-connect-fail")) {
        return expectConnectFail(
            args[2],
            try std.fmt.parseUnsigned(u16, args[3], 10),
            io,
        );
    }
    if (args.len == 5 and std.mem.eql(u8, args[1], "direct-client")) {
        return runDirectClient(
            args[2],
            try std.fmt.parseUnsigned(u16, args[3], 10),
            args[4],
            io,
        );
    }
    if (args.len == 7 and std.mem.eql(u8, args[1], "resolve-only")) {
        const family: net.IpAddress.Family = if (std.mem.eql(u8, args[5], "4")) .ip4 else if (std.mem.eql(u8, args[5], "6")) .ip6 else return error.InvalidFamily;
        const target = try resolveFake(args[2], try std.fmt.parseUnsigned(u16, args[3], 10), args[4], family, try std.fmt.parseUnsigned(u16, args[6], 10), io);
        var stdout_buffer: [256]u8 = undefined;
        var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
        try stdout_writer.interface.print("PASS DNS {s} {f}\n", .{ args[4], target });
        try stdout_writer.interface.flush();
        return;
    }
    if (args.len == 7 and std.mem.eql(u8, args[1], "http-client")) {
        const family: net.IpAddress.Family = if (std.mem.eql(u8, args[5], "4")) .ip4 else if (std.mem.eql(u8, args[5], "6")) .ip6 else return error.InvalidFamily;
        return runHttpClient(
            args[2],
            try std.fmt.parseUnsigned(u16, args[3], 10),
            args[4],
            family,
            try std.fmt.parseUnsigned(u16, args[6], 10),
            io,
        );
    }
    if (args.len == 8 and std.mem.eql(u8, args[1], "client")) {
        const family: net.IpAddress.Family = if (std.mem.eql(u8, args[5], "4")) .ip4 else if (std.mem.eql(u8, args[5], "6")) .ip6 else return error.InvalidFamily;
        return runClient(
            args[2],
            try std.fmt.parseUnsigned(u16, args[3], 10),
            args[4],
            family,
            try std.fmt.parseUnsigned(u16, args[6], 10),
            args[7],
            io,
        );
    }
    return error.InvalidArguments;
}

fn expectConnectFail(address: []const u8, port: u16, io: Io) !void {
    const target = try net.IpAddress.parse(address, port);
    const stream = xray.net.session.connectTargetTimeout(
        .{ .address = target },
        io,
        .{ .duration = .{ .raw = Io.Duration.fromSeconds(5), .clock = .awake } },
    ) catch |err| switch (err) {
        error.ConnectionRefused => {
            var stdout_buffer: [256]u8 = undefined;
            var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
            try stdout_writer.interface.print("PASS connect to {f} was refused as expected\n", .{target});
            try stdout_writer.interface.flush();
            return;
        },
        else => return err,
    };
    stream.close(io);
    return error.UnexpectedConnectSuccess;
}

fn runServer(io: Io) !void {
    var dns_address = try net.IpAddress.parse("127.0.0.1", dns_port);
    var dns_listener = try dns_address.listen(io, .{ .reuse_address = true });
    defer dns_listener.deinit(io);
    var echo4_address = try net.IpAddress.parse("127.0.0.1", echo_port);
    var echo4_listener = try echo4_address.listen(io, .{ .reuse_address = true });
    defer echo4_listener.deinit(io);
    var echo6_address = try net.IpAddress.parse("::1", echo_port);
    var echo6_listener = try echo6_address.listen(io, .{ .reuse_address = true });
    defer echo6_listener.deinit(io);

    var stdout_buffer: [128]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.writeAll("READY\n");
    try stdout_writer.interface.flush();

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, dnsAcceptLoop, .{ &dns_listener, io });
    try group.concurrent(io, echoAcceptLoop, .{ &echo4_listener, io });
    try group.concurrent(io, echoAcceptLoop, .{ &echo6_listener, io });
    try group.await(io);
}

fn runLiteralServer(io: Io) !void {
    var dns_address = try net.IpAddress.parse("127.0.0.1", dns_port);
    var dns_listener = try dns_address.listen(io, .{ .reuse_address = true });
    defer dns_listener.deinit(io);
    var echo4_address = try net.IpAddress.parse("127.0.0.1", echo_port);
    var echo4_listener = try echo4_address.listen(io, .{ .reuse_address = true });
    defer echo4_listener.deinit(io);
    var echo6_address = try net.IpAddress.parse("::1", echo_port);
    var echo6_listener = try echo6_address.listen(io, .{ .reuse_address = true });
    defer echo6_listener.deinit(io);
    var literal4_address = try net.IpAddress.parse("203.0.113.10", echo_port);
    var literal4_listener = try literal4_address.listen(io, .{ .reuse_address = true });
    defer literal4_listener.deinit(io);
    var literal6_address = try net.IpAddress.parse("2001:db8:100::10", echo_port);
    var literal6_listener = try literal6_address.listen(io, .{ .reuse_address = true });
    defer literal6_listener.deinit(io);

    var stdout_buffer: [128]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.writeAll("READY\n");
    try stdout_writer.interface.flush();

    var group: Io.Group = .init;
    defer group.cancel(io);
    try group.concurrent(io, dnsAcceptLoop, .{ &dns_listener, io });
    try group.concurrent(io, echoAcceptLoop, .{ &echo4_listener, io });
    try group.concurrent(io, echoAcceptLoop, .{ &echo6_listener, io });
    try group.concurrent(io, echoAcceptLoop, .{ &literal4_listener, io });
    try group.concurrent(io, echoAcceptLoop, .{ &literal6_listener, io });
    try group.await(io);
}

fn dnsAcceptLoop(listener: *net.Server, io: Io) Io.Cancelable!void {
    var group: Io.Group = .init;
    defer group.cancel(io);
    while (true) {
        const stream = listener.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        group.concurrent(io, serveDns, .{ stream, io }) catch {
            stream.close(io);
            continue;
        };
    }
}

fn serveDns(stream: net.Stream, io: Io) Io.Cancelable!void {
    defer stream.close(io);
    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var length_bytes: [2]u8 = undefined;
    reader.interface.readSliceAll(&length_bytes) catch return;
    const query_length = std.mem.readInt(u16, &length_bytes, .big);
    if (query_length > 2048) return;
    var query: [2048]u8 = undefined;
    reader.interface.readSliceAll(query[0..query_length]) catch return;

    var name_buffer: [255]u8 = undefined;
    const question = dns.parseQuestion(query[0..query_length], &name_buffer) catch return;
    var response_buffer: [2048]u8 = undefined;
    const response = if (std.mem.eql(u8, question.name, "echo4.lab") and question.qtype == dns.qtype_a)
        dns.buildAResponse(&response_buffer, question, .{ 127, 0, 0, 1 }, 30) catch return
    else if (std.mem.eql(u8, question.name, "echo6.lab") and question.qtype == dns.qtype_aaaa)
        dns.buildAAAAResponse(&response_buffer, question, [_]u8{0} ** 15 ++ .{1}, 30) catch return
    else
        dns.buildEmptyResponse(&response_buffer, question) catch return;

    std.mem.writeInt(u16, &length_bytes, @intCast(response.len), .big);
    var write_buffer: [4096]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    writer.interface.writeAll(&length_bytes) catch return;
    writer.interface.writeAll(response) catch return;
    writer.interface.flush() catch return;
}

fn echoAcceptLoop(listener: *net.Server, io: Io) Io.Cancelable!void {
    var group: Io.Group = .init;
    defer group.cancel(io);
    while (true) {
        const stream = listener.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        group.concurrent(io, serveEcho, .{ stream, io }) catch {
            stream.close(io);
            continue;
        };
    }
}

fn serveEcho(stream: net.Stream, io: Io) Io.Cancelable!void {
    defer stream.close(io);
    var storage: [4096]u8 = undefined;
    while (true) {
        var read_buffer: [4096]u8 = undefined;
        var reader = stream.reader(io, &read_buffer);
        var slices = [_][]u8{&storage};
        const count = reader.interface.readVec(&slices) catch |err| switch (err) {
            error.EndOfStream => return,
            else => return,
        };
        if (count == 0) return;
        var write_buffer: [4096]u8 = undefined;
        var writer = stream.writer(io, &write_buffer);
        writer.interface.writeAll(storage[0..count]) catch return;
        writer.interface.flush() catch return;
    }
}

fn runClient(
    dns_server: []const u8,
    server_port: u16,
    domain: []const u8,
    family: net.IpAddress.Family,
    target_port: u16,
    payload: []const u8,
    io: Io,
) !void {
    const target = try resolveFake(dns_server, server_port, domain, family, target_port, io);

    try echoRoundTrip(target, payload, io);

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.print("PASS {s} {f}\n", .{ domain, target });
    try stdout_writer.interface.flush();
}

fn runDirectClient(address: []const u8, port: u16, payload: []const u8, io: Io) !void {
    const target = try net.IpAddress.parse(address, port);
    try echoRoundTrip(target, payload, io);

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.print("PASS cached {f}\n", .{target});
    try stdout_writer.interface.flush();
}

fn echoRoundTrip(target: net.IpAddress, payload: []const u8, io: Io) !void {
    const stream = try xray.net.session.connectTargetTimeout(
        .{ .address = target },
        io,
        .{ .duration = .{ .raw = Io.Duration.fromSeconds(5), .clock = .awake } },
    );
    defer stream.close(io);
    var write_buffer: [4096]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.writeAll(payload);
    try writer.interface.flush();
    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var echoed = try std.ArrayList(u8).initCapacity(std.heap.page_allocator, payload.len);
    defer echoed.deinit(std.heap.page_allocator);
    try echoed.resize(std.heap.page_allocator, payload.len);
    try reader.interface.readSliceAll(echoed.items);
    if (!std.mem.eql(u8, payload, echoed.items)) return error.EchoMismatch;
}

fn runHttpClient(
    dns_server: []const u8,
    server_port: u16,
    domain: []const u8,
    family: net.IpAddress.Family,
    target_port: u16,
    io: Io,
) !void {
    const target = try resolveFake(dns_server, server_port, domain, family, target_port, io);
    const stream = try xray.net.session.connectTargetTimeout(
        .{ .address = target },
        io,
        .{ .duration = .{ .raw = Io.Duration.fromSeconds(10), .clock = .awake } },
    );
    defer stream.close(io);

    var request_buffer: [1024]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buffer,
        "GET / HTTP/1.1\r\nHost: {s}\r\nUser-Agent: xray-zig-ebpf-lab/1\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        .{domain},
    );
    var write_buffer: [4096]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.writeAll(request);
    try writer.interface.flush();

    const ready = try xray.net.session.waitReadableTimeout(stream, stream, 20_000);
    if (!ready.first) return error.HttpResponseTimeout;
    var response_buffer: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &response_buffer);
    var first_chunk: [16 * 1024]u8 = undefined;
    var slices = [_][]u8{&first_chunk};
    const response_len = try reader.interface.readVec(&slices);
    if (response_len == 0) return error.EmptyHttpResponse;
    const status = try parseHttpStatus(first_chunk[0..response_len]);
    if (status < 200 or status >= 400) return error.UnexpectedHttpStatus;

    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.print(
        "PASS WAN HTTP {s} {f} status={d} first_bytes={d}\n",
        .{ domain, target, status, response_len },
    );
    try stdout_writer.interface.flush();
}

fn resolveFake(
    dns_server: []const u8,
    server_port: u16,
    domain: []const u8,
    family: net.IpAddress.Family,
    target_port: u16,
    io: Io,
) !net.IpAddress {
    var query_buffer: [512]u8 = undefined;
    const query_type: u16 = if (family == .ip4) dns.qtype_a else dns.qtype_aaaa;
    const query = try dns.buildQuery(&query_buffer, 0xeb9f, domain, query_type);
    const server = try net.IpAddress.parse(dns_server, server_port);
    var bind_address: net.IpAddress = switch (server) {
        .ip4 => .{ .ip4 = net.Ip4Address.unspecified(0) },
        .ip6 => .{ .ip6 = net.Ip6Address.unspecified(0) },
    };
    var socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);
    try socket.send(io, &server, query);
    var response_buffer: [2048]u8 = undefined;
    const message = try socket.receiveTimeout(io, &response_buffer, .{ .duration = .{ .raw = Io.Duration.fromSeconds(5), .clock = .awake } });
    return parseDnsAddress(message.data, family, target_port);
}

fn parseHttpStatus(response: []const u8) !u16 {
    const line_end = std.mem.indexOf(u8, response, "\r\n") orelse return error.InvalidHttpResponse;
    const line = response[0..line_end];
    if (!std.mem.startsWith(u8, line, "HTTP/")) return error.InvalidHttpResponse;
    const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse return error.InvalidHttpResponse;
    const status_start = first_space + 1;
    if (line.len < status_start + 3) return error.InvalidHttpResponse;
    return std.fmt.parseUnsigned(u16, line[status_start .. status_start + 3], 10) catch return error.InvalidHttpResponse;
}

fn parseDnsAddress(packet: []const u8, family: net.IpAddress.Family, port: u16) !net.IpAddress {
    if (packet.len < 12 or packet[3] & 0x0f != 0) return error.InvalidDnsResponse;
    var offset: usize = 12;
    var questions = std.mem.readInt(u16, packet[4..6], .big);
    while (questions > 0) : (questions -= 1) {
        offset = try skipName(packet, offset);
        if (packet.len - offset < 4) return error.InvalidDnsResponse;
        offset += 4;
    }
    var answers = std.mem.readInt(u16, packet[6..8], .big);
    while (answers > 0) : (answers -= 1) {
        offset = try skipName(packet, offset);
        if (packet.len - offset < 10) return error.InvalidDnsResponse;
        const record_type = std.mem.readInt(u16, packet[offset..][0..2], .big);
        const data_len = std.mem.readInt(u16, packet[offset + 8 ..][0..2], .big);
        offset += 10;
        if (packet.len - offset < data_len) return error.InvalidDnsResponse;
        const data = packet[offset..][0..data_len];
        if (family == .ip4 and record_type == dns.qtype_a and data.len == 4)
            return .{ .ip4 = .{ .bytes = data[0..4].*, .port = port } };
        if (family == .ip6 and record_type == dns.qtype_aaaa and data.len == 16)
            return .{ .ip6 = .{ .bytes = data[0..16].*, .port = port, .interface = .none } };
        offset += data_len;
    }
    return error.NoAddressReturned;
}

fn skipName(packet: []const u8, start: usize) !usize {
    var offset = start;
    while (true) {
        if (offset >= packet.len) return error.InvalidDnsResponse;
        const length = packet[offset];
        if (length & 0xc0 == 0xc0) {
            if (packet.len - offset < 2) return error.InvalidDnsResponse;
            return offset + 2;
        }
        if (length & 0xc0 != 0) return error.InvalidDnsResponse;
        offset += 1;
        if (length == 0) return offset;
        if (packet.len - offset < length) return error.InvalidDnsResponse;
        offset += length;
    }
}

test "parses HTTP status line" {
    try std.testing.expectEqual(@as(u16, 200), try parseHttpStatus("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"));
    try std.testing.expectError(error.InvalidHttpResponse, parseHttpStatus("not-http\r\n"));
}
