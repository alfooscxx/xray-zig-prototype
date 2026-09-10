const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const posix = std.posix;

const config = @import("../config/mod.zig");
const log = @import("../log.zig");
const protocol = @import("protocol.zig");
const session = @import("../net/session.zig");
const upstream = @import("upstream.zig");

const response_capacity = 4096;
const query_timeout_seconds = 5;

pub fn connect(
    target: session.HostTarget,
    preferred_family: ?net.IpAddress.Family,
    dns_config: config.DnsConfig,
    dispatcher: session.Dispatcher,
    io: Io,
) !net.Stream {
    var addresses: [32]net.IpAddress = undefined;
    var addresses_len: usize = 0;

    const families: [2]net.IpAddress.Family = if (preferred_family) |family|
        .{ family, otherFamily(family) }
    else
        .{ .ip4, .ip6 };
    for (families) |family| {
        addresses_len += try lookupFamily(
            target,
            family,
            dns_config,
            dispatcher,
            addresses[addresses_len..],
            io,
        );
    }

    if (addresses_len == 0) return error.NoAddressReturned;
    return connectAddresses(addresses[0..addresses_len], io);
}

fn lookupFamily(
    target: session.HostTarget,
    family: net.IpAddress.Family,
    dns_config: config.DnsConfig,
    dispatcher: session.Dispatcher,
    addresses: []net.IpAddress,
    io: Io,
) !usize {
    const query_id: u16 = switch (family) {
        .ip4 => 0xa4a4,
        .ip6 => 0xaaaa,
    };
    const query_type: u16 = switch (family) {
        .ip4 => protocol.qtype_a,
        .ip6 => protocol.qtype_aaaa,
    };

    var query_buffer: [512]u8 = undefined;
    const query = try protocol.buildQuery(&query_buffer, query_id, target.name.bytes, query_type);
    const server = dns_config.selectServer(target.name.bytes);
    var response_buffer: [response_capacity]u8 = undefined;
    const response = try exchange(query, target.name.bytes, server, dispatcher, &response_buffer, io);

    if (response.len < 4 or std.mem.readInt(u16, response[0..2], .big) != query_id) {
        return error.InvalidDnsResponse;
    }
    if (response[2] & 0x80 == 0 or response[3] & 0x0f != 0) {
        return error.DnsLookupFailed;
    }

    return parseAddresses(response, family, target.port, addresses);
}

fn otherFamily(family: net.IpAddress.Family) net.IpAddress.Family {
    return switch (family) {
        .ip4 => .ip6,
        .ip6 => .ip4,
    };
}

fn parseAddresses(
    packet: []const u8,
    family: net.IpAddress.Family,
    port: u16,
    addresses: []net.IpAddress,
) !usize {
    if (packet.len < 12) return error.InvalidDnsResponse;

    var offset: usize = 12;
    var questions = std.mem.readInt(u16, packet[4..6], .big);
    while (questions > 0) : (questions -= 1) {
        offset = try skipName(packet, offset);
        if (packet.len - offset < 4) return error.InvalidDnsResponse;
        offset += 4;
    }

    var count: usize = 0;
    var answers = std.mem.readInt(u16, packet[6..8], .big);
    while (answers > 0) : (answers -= 1) {
        offset = try skipName(packet, offset);
        if (packet.len - offset < 10) return error.InvalidDnsResponse;
        const record_type = std.mem.readInt(u16, packet[offset..][0..2], .big);
        const data_len = std.mem.readInt(u16, packet[offset + 8 ..][0..2], .big);
        offset += 10;
        if (packet.len - offset < data_len) return error.InvalidDnsResponse;
        const data = packet[offset..][0..data_len];
        defer offset += data_len;

        if (count == addresses.len) continue;
        if (family == .ip4 and record_type == protocol.qtype_a and data.len == 4) {
            addresses[count] = .{ .ip4 = .{
                .bytes = data[0..4].*,
                .port = port,
            } };
            count += 1;
        } else if (family == .ip6 and record_type == protocol.qtype_aaaa and data.len == 16) {
            addresses[count] = .{ .ip6 = .{
                .bytes = data[0..16].*,
                .port = port,
            } };
            count += 1;
        }
    }
    return count;
}

fn skipName(packet: []const u8, start: usize) !usize {
    var offset = start;
    while (true) {
        if (offset >= packet.len) return error.InvalidDnsResponse;
        const label_len = packet[offset];
        if (label_len & 0xc0 == 0xc0) {
            if (packet.len - offset < 2) return error.InvalidDnsResponse;
            return offset + 2;
        }
        if (label_len & 0xc0 != 0) return error.InvalidDnsResponse;
        offset += 1;
        if (label_len == 0) return offset;
        if (packet.len - offset < label_len) return error.InvalidDnsResponse;
        offset += label_len;
    }
}

fn connectAddresses(addresses: []const net.IpAddress, io: Io) !net.Stream {
    const options: net.IpAddress.ConnectOptions = .{
        .mode = .stream,
        .protocol = .tcp,
    };

    var results_buffer: [32]net.IpAddress.ConnectError!net.Stream = undefined;
    var results: Io.Queue(net.IpAddress.ConnectError!net.Stream) = .init(&results_buffer);
    var connections = io.async(connectAddressesConcurrent, .{ addresses, io, &results, options });
    defer {
        connections.cancel(io) catch {};
        while (results.getOneUncancelable(io)) |loser| {
            if (loser) |stream| stream.close(io) else |_| {}
        } else |_| {}
    }

    var last_error: ?net.IpAddress.ConnectError = null;
    while (results.getOne(io)) |result| {
        if (result) |stream| {
            return stream;
        } else |err| {
            last_error = err;
        }
    } else |err| switch (err) {
        error.Canceled => |e| return e,
        error.Closed => {
            try connections.await(io);
            return last_error orelse error.NoAddressReturned;
        },
    }
}

fn connectAddressesConcurrent(
    addresses: []const net.IpAddress,
    io: Io,
    results: *Io.Queue(net.IpAddress.ConnectError!net.Stream),
    options: net.IpAddress.ConnectOptions,
) Io.Cancelable!void {
    defer results.close(io);
    var group: Io.Group = .init;
    defer group.cancel(io);
    for (addresses) |address| {
        group.async(io, enqueueConnection, .{ address, io, results, options });
    }
    try group.await(io);
}

fn enqueueConnection(
    address: net.IpAddress,
    io: Io,
    results: *Io.Queue(net.IpAddress.ConnectError!net.Stream),
    options: net.IpAddress.ConnectOptions,
) Io.Cancelable!void {
    const result = address.connect(io, options) catch |err| switch (err) {
        error.Canceled => |e| return e,
        else => |e| e,
    };
    errdefer if (result) |stream| stream.close(io) else |_| {};
    results.putOne(io, result) catch |err| switch (err) {
        error.Canceled => |e| return e,
        error.Closed => unreachable,
    };
}

pub fn exchange(
    packet: []const u8,
    domain: []const u8,
    server: *const config.DnsServer,
    dispatcher: session.Dispatcher,
    response_buffer: []u8,
    io: Io,
) ![]const u8 {
    if (packet.len > response_capacity) return error.DnsResponseTooLarge;
    const upstream_address = upstream.parseAddress(server.resolver) catch return error.UnsupportedDnsUpstream;

    if (std.mem.eql(u8, server.outbound_tag, "direct")) {
        const udp_response = try exchangeDirectUdp(packet, upstream_address, response_buffer, io);
        if (udp_response.len < 3 or udp_response[2] & 0x02 == 0) return udp_response;
    }

    return exchangeTcp(packet, domain, server, upstream_address, dispatcher, response_buffer, io);
}

fn exchangeDirectUdp(
    packet: []const u8,
    upstream_address: net.IpAddress,
    response_buffer: []u8,
    io: Io,
) ![]const u8 {
    var local_address: net.IpAddress = switch (upstream_address) {
        .ip4 => .{ .ip4 = net.Ip4Address.unspecified(0) },
        .ip6 => .{ .ip6 = net.Ip6Address.unspecified(0) },
    };
    var socket = try local_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    try socket.send(io, &upstream_address, packet);
    const message = try socket.receiveTimeout(io, response_buffer, .{
        .duration = .{
            .raw = Io.Duration.fromSeconds(query_timeout_seconds),
            .clock = .awake,
        },
    });
    if (!std.meta.eql(message.from, upstream_address)) return error.InvalidDnsResponse;
    if (message.data.len < 2 or packet.len < 2 or
        !std.mem.eql(u8, message.data[0..2], packet[0..2]))
    {
        return error.InvalidDnsResponse;
    }
    return message.data;
}

fn exchangeTcp(
    packet: []const u8,
    domain: []const u8,
    server: *const config.DnsServer,
    upstream_address: net.IpAddress,
    dispatcher: session.Dispatcher,
    response_buffer: []u8,
    io: Io,
) ![]const u8 {
    // Close the local endpoint before waiting for the dispatched task.  A
    // DNS-over-TCP peer may keep its connection open after a complete
    // response, so the close is what wakes a bridge blocked on that stream.
    var group: Io.Group = .init;
    defer group.cancel(io);

    var pair = try createLoopbackPair(io);
    defer pair[0].close(io);

    var framed_query: [response_capacity + 2]u8 = undefined;
    var length_bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &length_bytes, @intCast(packet.len), .big);
    @memcpy(framed_query[0..2], &length_bytes);
    @memcpy(framed_query[2 .. packet.len + 2], packet);

    while (true) {
        group.concurrent(io, dispatchQuery, .{
            pair[1],
            dispatcher,
            upstream_address,
            domain,
            server.outbound_tag,
            framed_query[0 .. packet.len + 2],
            io,
        }) catch {
            io.sleep(Io.Duration.fromMilliseconds(10), .awake) catch |err| {
                pair[1].close(io);
                return err;
            };
            continue;
        };
        break;
    }

    try receiveAllTimeout(pair[0], &length_bytes, io);
    const response_len = std.mem.readInt(u16, &length_bytes, .big);
    if (response_len > response_buffer.len) return error.DnsResponseTooLarge;
    try receiveAllTimeout(pair[0], response_buffer[0..response_len], io);
    return response_buffer[0..response_len];
}

fn createLoopbackPair(io: Io) ![2]net.Stream {
    if (builtin.os.tag == .linux) return createLocalPair();

    var address = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const client = try listener.socket.address.connect(io, .{ .mode = .stream, .protocol = .tcp });
    errdefer client.close(io);
    const server = try listener.accept(io);
    return .{ client, server };
}

fn createLocalPair() ![2]net.Stream {
    var fds: [2]posix.socket_t = undefined;
    while (true) switch (posix.errno(posix.system.socketpair(
        posix.AF.UNIX,
        posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
        0,
        &fds,
    ))) {
        .SUCCESS => break,
        .INTR => continue,
        .MFILE, .NFILE, .NOBUFS, .NOMEM => return error.SystemResources,
        else => return error.Unexpected,
    };

    const address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    return .{
        .{ .socket = .{ .handle = fds[0], .address = address } },
        .{ .socket = .{ .handle = fds[1], .address = address } },
    };
}

fn dispatchQuery(
    stream: net.Stream,
    dispatcher: session.Dispatcher,
    upstream_address: net.IpAddress,
    domain: []const u8,
    outbound_tag: []const u8,
    framed_query: []const u8,
    io: Io,
) Io.Cancelable!void {
    defer stream.close(io);
    dispatcher.dispatch(stream, .{
        .target = .{ .address = upstream_address },
        .sniffed_domain = domain,
        .outbound_tag = outbound_tag,
    }, .{ .bytes = framed_query }, io) catch |err| {
        log.warn("dns outbound {s} dispatch failed: {s}\n", .{ outbound_tag, @errorName(err) });
        return;
    };
}

fn receiveAllTimeout(stream: net.Stream, buffer: []u8, io: Io) !void {
    var used: usize = 0;
    while (used < buffer.len) {
        const message = try stream.socket.receiveTimeout(io, buffer[used..], .{
            .duration = .{
                .raw = Io.Duration.fromSeconds(query_timeout_seconds),
                .clock = .awake,
            },
        });
        if (message.data.len == 0) return error.EndOfStream;
        used += message.data.len;
    }
}

test "routed DNS returns a complete response before the dispatched stream closes" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const Harness = struct {
        const response = "immediate-response";
        const hold_open_ms = 500;

        fn dispatch(
            _: *anyopaque,
            stream: net.Stream,
            _: session.Session,
            _: session.Preface,
            io: Io,
        ) !void {
            var length_bytes: [2]u8 = undefined;
            std.mem.writeInt(u16, &length_bytes, response.len, .big);
            var write_buffer: [64]u8 = undefined;
            var writer = stream.writer(io, &write_buffer);
            try writer.interface.writeAll(&length_bytes);
            try writer.interface.writeAll(response);
            try writer.interface.flush();

            // DNS-over-TCP permits the server to retain the connection after
            // one response. Model that without sleeping so closing the local
            // socketpair can wake this poll immediately.
            _ = session.waitReadableTimeout(stream, stream, hold_open_ms) catch {};
        }
    };

    var threaded: Io.Threaded = .init(std.testing.allocator, .{
        .stack_size = 1024 * 1024,
        .concurrent_limit = .limited(2),
    });
    defer threaded.deinit();
    const io = threaded.io();

    var harness: u8 = 0;
    const dispatcher: session.Dispatcher = .{
        .context = &harness,
        .dispatch_fn = Harness.dispatch,
    };
    var domains: [0]config.DomainRule = .{};
    const server: config.DnsServer = .{
        .resolver = "127.0.0.1:53",
        .outbound_tag = "proxy",
        .domains = &domains,
    };
    const upstream_address: net.IpAddress = .{ .ip4 = .loopback(53) };
    var response_buffer: [response_capacity]u8 = undefined;

    const started_ns = Io.Timestamp.now(io, .awake).nanoseconds;
    const response = try exchangeTcp(
        "query",
        "example.test",
        &server,
        upstream_address,
        dispatcher,
        &response_buffer,
        io,
    );
    const elapsed_ns = Io.Timestamp.now(io, .awake).nanoseconds - started_ns;

    try std.testing.expectEqualStrings(Harness.response, response);
    try std.testing.expect(elapsed_ns < 200 * std.time.ns_per_ms);
}
