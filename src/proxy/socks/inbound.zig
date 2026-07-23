const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const log = @import("../../log.zig");
const session = @import("../../net/session.zig");

const SocksError = error{
    InvalidVersion,
    InvalidReservedByte,
    NoSupportedAuthMethod,
    UnsupportedCommand,
    UnsupportedAddressType,
    InvalidDomain,
};

const Reply = enum(u8) {
    succeeded = 0x00,
    general_failure = 0x01,
    network_unreachable = 0x03,
    host_unreachable = 0x04,
    connection_refused = 0x05,
    command_not_supported = 0x07,
    address_type_not_supported = 0x08,
};

const Request = struct {
    command: u8,
    target: session.Target,
};

pub fn run(inbound: config.Inbound, dispatcher: session.Dispatcher, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) !void {
    var address = try bindAddress(inbound.listen, inbound.port);
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    var group: Io.Group = .init;
    defer group.cancel(io);

    {
        try log_mutex.lock(io);
        defer log_mutex.unlock(io);
        try log_writer.print("socks inbound {s} listening on {f}\n", .{ inbound.tag orelse "-", server.socket.address });
        try log_writer.flush();
    }

    while (true) {
        const stream = server.accept(io) catch |err| switch (err) {
            error.Canceled => return err,
            else => |e| return e,
        };
        var capacity_warned = false;
        while (true) {
            group.concurrent(io, handleConnection, .{ stream, dispatcher, inbound.tag, io, log_writer, log_mutex }) catch {
                if (!capacity_warned) {
                    log.warn("socks inbound at worker capacity; queueing connection\n", .{});
                    capacity_warned = true;
                }
                io.sleep(Io.Duration.fromMilliseconds(10), .awake) catch |err| {
                    stream.close(io);
                    return err;
                };
                continue;
            };
            break;
        }
    }
}

fn bindAddress(listen: []const u8, port: u16) !net.IpAddress {
    return net.IpAddress.parse(listen, port) catch error.UnsupportedListenAddress;
}

fn handleConnection(stream: net.Stream, dispatcher: session.Dispatcher, inbound_tag: ?[]const u8, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) Io.Cancelable!void {
    defer stream.close(io);

    var input: SocketReader = .{ .stream = stream, .io = io };

    var write_buffer: [256]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    const output = &writer.interface;

    negotiateAuth(&input, output) catch return;

    var domain_buffer: [net.HostName.max_len]u8 = undefined;
    const request = readRequest(&input, &domain_buffer) catch |err| {
        writeReply(output, replyForRequestError(err)) catch {};
        return;
    };

    if (request.command != 0x01) {
        writeReply(output, .command_not_supported) catch {};
        return;
    }

    writeReply(output, .succeeded) catch return;
    dispatcher.dispatch(stream, .{
        .target = request.target,
        .inbound_tag = inbound_tag,
        .sniffed_domain = domainForTarget(request.target),
    }, .{}, io) catch |err| {
        log_mutex.lock(io) catch return;
        defer log_mutex.unlock(io);
        log_writer.print("socks dispatch failed: {s}\n", .{@errorName(err)}) catch {};
        log_writer.flush() catch {};
        _ = replyForConnectError(err);
        return;
    };
}

fn domainForTarget(target: session.Target) ?[]const u8 {
    return switch (target) {
        .host => |host| host.name.bytes,
        .address => null,
    };
}

const SocketReader = struct {
    stream: net.Stream,
    io: Io,
    buffer: [512]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn peek(self: *SocketReader, len: usize) ![]u8 {
        if (len > self.buffer.len) return error.MessageTooLarge;
        while (self.end - self.start < len) {
            if (self.start != 0) {
                std.mem.copyForwards(u8, self.buffer[0 .. self.end - self.start], self.buffer[self.start..self.end]);
                self.end -= self.start;
                self.start = 0;
            }
            const message = try self.stream.socket.receive(self.io, self.buffer[self.end..]);
            if (message.data.len == 0) return error.EndOfStream;
            self.end += message.data.len;
        }
        return self.buffer[self.start..][0..len];
    }

    fn toss(self: *SocketReader, len: usize) void {
        std.debug.assert(len <= self.end - self.start);
        self.start += len;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
    }
};

fn negotiateAuth(input: anytype, output: *Io.Writer) !void {
    const header = try input.peek(2);
    if (header[0] != 0x05) return error.InvalidVersion;
    const method_count = header[1];
    const message = try input.peek(2 + method_count);
    var supports_no_auth = false;
    for (message[2..]) |method| {
        if (method == 0x00) supports_no_auth = true;
    }
    input.toss(message.len);

    if (!supports_no_auth) {
        try output.writeAll(&.{ 0x05, 0xff });
        try output.flush();
        return error.NoSupportedAuthMethod;
    }

    try output.writeAll(&.{ 0x05, 0x00 });
    try output.flush();
}

fn readRequest(input: anytype, domain_buffer: *[net.HostName.max_len]u8) !Request {
    const header = try input.peek(5);
    if (header[0] != 0x05) return error.InvalidVersion;
    const command = header[1];
    if (header[2] != 0x00) return error.InvalidReservedByte;

    const address_type = header[3];
    const message_len: usize = switch (address_type) {
        0x01 => 10,
        0x03 => 5 + @as(usize, header[4]) + 2,
        0x04 => 22,
        else => return error.UnsupportedAddressType,
    };
    const message = try input.peek(message_len);
    const target: session.Target = switch (address_type) {
        0x01 => .{ .address = .{ .ip4 = .{
            .bytes = message[4..8].*,
            .port = std.mem.readInt(u16, message[8..10], .big),
        } } },
        0x03 => blk: {
            const len = message[4];
            if (len == 0 or len > domain_buffer.len) return error.InvalidDomain;
            @memcpy(domain_buffer[0..len], message[5..][0..len]);
            const port_offset = 5 + @as(usize, len);
            const port = std.mem.readInt(u16, message[port_offset..][0..2], .big);
            break :blk .{ .host = .{
                .name = try net.HostName.init(domain_buffer[0..len]),
                .port = port,
            } };
        },
        0x04 => .{ .address = .{ .ip6 = .{
            .bytes = message[4..20].*,
            .port = std.mem.readInt(u16, message[20..22], .big),
        } } },
        else => return error.UnsupportedAddressType,
    };
    input.toss(message.len);

    return .{
        .command = command,
        .target = target,
    };
}

fn writeReply(output: *Io.Writer, reply: Reply) !void {
    try output.writeAll(&.{
        0x05,
        @intFromEnum(reply),
        0x00,
        0x01,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    });
    try output.flush();
}

fn replyForRequestError(err: anyerror) Reply {
    return switch (err) {
        error.UnsupportedCommand => .command_not_supported,
        error.UnsupportedAddressType => .address_type_not_supported,
        else => .general_failure,
    };
}

fn replyForConnectError(err: anyerror) Reply {
    return switch (err) {
        error.ConnectionRefused => .connection_refused,
        error.NetworkUnreachable => .network_unreachable,
        error.HostUnreachable,
        error.UnknownHostName,
        error.NoAddressReturned,
        => .host_unreachable,
        else => .general_failure,
    };
}

test "parses bind address" {
    const address = try bindAddress("127.0.0.1", 1080);
    try std.testing.expectEqual(@as(u16, 1080), address.getPort());
}

test "reads IPv4 CONNECT request" {
    var reader: Io.Reader = .fixed(&.{
        0x05, 0x01, 0x00, 0x01,
        127,  0,    0,    1,
        0x04, 0x38,
    });
    var domain_buffer: [net.HostName.max_len]u8 = undefined;

    const request = try readRequest(&reader, &domain_buffer);

    try std.testing.expectEqual(@as(u8, 0x01), request.command);
    switch (request.target) {
        .address => |address| {
            try std.testing.expectEqual(@as(u16, 1080), address.getPort());
            try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &address.ip4.bytes);
        },
        .host => return error.UnexpectedHostTarget,
    }
}

test "reads domain CONNECT request" {
    var reader: Io.Reader = .fixed(&.{
        0x05, 0x01, 0x00, 0x03,
        11,   'e',  'x',  'a',
        'm',  'p',  'l',  'e',
        '.',  'c',  'o',  'm',
        0x01, 0xbb,
    });
    var domain_buffer: [net.HostName.max_len]u8 = undefined;

    const request = try readRequest(&reader, &domain_buffer);

    switch (request.target) {
        .address => return error.UnexpectedAddressTarget,
        .host => |host| {
            try std.testing.expectEqual(@as(u16, 443), host.port);
            try std.testing.expectEqualStrings("example.com", host.name.bytes);
        },
    }
}
