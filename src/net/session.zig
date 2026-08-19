const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const net = Io.net;
const posix = std.posix;

const reality = @import("../transport/reality/client.zig");
pub const RawReactor = @import("reactor.zig").Reactor;
pub const datagram = @import("datagram.zig");

test {
    _ = datagram;
    _ = @import("../proxy/tun/udp_packet.zig");
    _ = @import("../proxy/tun/udp.zig");
    _ = @import("../proxy/freedom/udp.zig");
    _ = @import("../proxy/vless/udp.zig");
}

pub const max_preface_len = 2048;
pub const response_header_timeout_ms = 60 * 1000;
pub const connection_idle_timeout_ms = 300 * 1000;
const deadline_cancellation_poll_ns = std.time.ns_per_s;

pub const Target = union(enum) {
    address: net.IpAddress,
    host: HostTarget,

    pub fn port(self: Target) u16 {
        return switch (self) {
            .address => |address| address.getPort(),
            .host => |host| host.port,
        };
    }
};

pub const HostTarget = struct {
    name: net.HostName,
    port: u16,
};

pub const Session = struct {
    target: Target,
    inbound_tag: ?[]const u8 = null,
    sniffed_domain: ?[]const u8 = null,
    outbound_tag: ?[]const u8 = null,
    preferred_family: ?net.IpAddress.Family = null,
};

pub const Preface = struct {
    bytes: []const u8 = &.{},
};

pub const Dispatcher = struct {
    context: *anyopaque,
    dispatch_fn: *const fn (*anyopaque, net.Stream, Session, Preface, Io) anyerror!void,

    pub fn dispatch(self: Dispatcher, client: net.Stream, sess: Session, preface: Preface, io: Io) !void {
        try self.dispatch_fn(self.context, client, sess, preface, io);
    }
};

pub fn targetFromHostBytes(host: []const u8, port: u16) !Target {
    if (net.IpAddress.parse(host, port)) |address| {
        return .{ .address = address };
    } else |_| {
        return .{ .host = .{
            .name = try net.HostName.init(host),
            .port = port,
        } };
    }
}

pub fn connectHostOrIp(host: []const u8, port: u16, io: Io) !net.Stream {
    return connectTargetTimeout(try targetFromHostBytes(host, port), io, .none);
}

pub fn connectHostOrIpTimeout(host: []const u8, port: u16, io: Io, timeout: Io.Timeout) !net.Stream {
    return connectTargetTimeout(try targetFromHostBytes(host, port), io, timeout);
}

pub fn connectTarget(target: Target, io: Io) !net.Stream {
    return connectTargetTimeout(target, io, .none);
}

pub fn connectTargetTimeout(target: Target, io: Io, timeout: Io.Timeout) !net.Stream {
    const options: net.IpAddress.ConnectOptions = .{
        .mode = .stream,
        .protocol = .tcp,
    };

    const deadline = timeout.toTimestamp(io) orelse return switch (target) {
        .address => |address| address.connect(io, options),
        .host => |host| host.name.connect(io, host.port, options),
    };

    if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

    return switch (target) {
        .address => |address| connectIpDeadline(address, io, deadline),
        .host => |host| connectHostDeadline(host, io, deadline),
    };
}

fn connectHostDeadline(host: HostTarget, io: Io, deadline: Io.Clock.Timestamp) !net.Stream {
    var canonical_name_buffer: [net.HostName.max_len]u8 = undefined;
    var lookup_buffer: [32]net.HostName.LookupResult = undefined;
    var lookup_queue: Io.Queue(net.HostName.LookupResult) = .init(&lookup_buffer);
    try host.name.lookup(io, &lookup_queue, .{
        .port = host.port,
        .canonical_name_buffer = &canonical_name_buffer,
    });

    var last_error: ?net.IpAddress.ConnectError = null;
    while (lookup_queue.getOneUncancelable(io)) |result| switch (result) {
        .canonical_name => {},
        .address => |address| {
            return connectIpDeadline(address, io, deadline) catch |err| {
                last_error = err;
                continue;
            };
        },
    } else |err| switch (err) {
        error.Closed => return last_error orelse error.UnknownHostName,
    }
}

fn connectIpDeadline(address: net.IpAddress, io: Io, deadline: Io.Clock.Timestamp) net.IpAddress.ConnectError!net.Stream {
    const family: posix.sa_family_t = switch (address) {
        .ip4 => posix.AF.INET,
        .ip6 => posix.AF.INET6,
    };
    const socket_fd = openTcpSocket(family, io) catch |err| return err;
    errdefer _ = posix.system.close(socket_fd);

    switch (address) {
        .ip4 => |ip4| {
            var socket_address: posix.sockaddr.in = .{
                .port = std.mem.nativeToBig(u16, ip4.port),
                .addr = @bitCast(ip4.bytes),
            };
            try beginConnect(socket_fd, @ptrCast(&socket_address), @sizeOf(posix.sockaddr.in), io);
        },
        .ip6 => |ip6| {
            var socket_address: posix.sockaddr.in6 = .{
                .port = std.mem.nativeToBig(u16, ip6.port),
                .flowinfo = ip6.flow,
                .addr = ip6.bytes,
                .scope_id = ip6.interface.index,
            };
            try beginConnect(socket_fd, @ptrCast(&socket_address), @sizeOf(posix.sockaddr.in6), io);
        },
    }

    try waitConnected(socket_fd, io, deadline);
    try setBlocking(socket_fd);
    return .{ .socket = .{ .handle = socket_fd, .address = address } };
}

fn openTcpSocket(family: posix.sa_family_t, io: Io) net.IpAddress.ConnectError!posix.socket_t {
    while (true) {
        const rc = posix.system.socket(
            family,
            posix.SOCK.STREAM | posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK,
            posix.IPPROTO.TCP,
        );
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => try io.checkCancel(),
            .ACCES => return error.AccessDenied,
            .AFNOSUPPORT => return error.AddressFamilyUnsupported,
            .INVAL => return error.ProtocolUnsupportedBySystem,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .PROTONOSUPPORT => return error.ProtocolUnsupportedByAddressFamily,
            .PROTOTYPE => return error.SocketModeUnsupported,
            else => return error.Unexpected,
        }
    }
}

fn beginConnect(
    socket_fd: posix.socket_t,
    address: *const posix.sockaddr,
    address_len: posix.socklen_t,
    io: Io,
) net.IpAddress.ConnectError!void {
    while (true) switch (posix.errno(posix.system.connect(socket_fd, address, address_len))) {
        .SUCCESS, .ISCONN => return,
        .INTR => try io.checkCancel(),
        .AGAIN, .INPROGRESS, .ALREADY => return,
        else => |err| return connectError(err),
    };
}

fn waitConnected(socket_fd: posix.socket_t, io: Io, deadline: Io.Clock.Timestamp) net.IpAddress.ConnectError!void {
    var descriptor = [1]posix.pollfd{.{
        .fd = socket_fd,
        .events = posix.POLL.OUT,
        .revents = 0,
    }};

    while (true) {
        try io.checkCancel();
        const remaining_ns = deadline.durationFromNow(io).raw.toNanoseconds();
        if (remaining_ns <= 0) return error.Timeout;
        const poll_ns = @min(remaining_ns, deadline_cancellation_poll_ns);
        var poll_timeout: posix.timespec = .{
            .sec = @intCast(@divTrunc(poll_ns, std.time.ns_per_s)),
            .nsec = @intCast(@mod(poll_ns, std.time.ns_per_s)),
        };
        const ready = posix.ppoll(&descriptor, &poll_timeout, null) catch |err| switch (err) {
            error.SignalInterrupt => continue,
            else => |e| return e,
        };
        if (ready == 0) continue;

        var socket_error: i32 = 0;
        var error_len: posix.socklen_t = @sizeOf(@TypeOf(socket_error));
        const rc = posix.system.getsockopt(
            socket_fd,
            posix.SOL.SOCKET,
            posix.SO.ERROR,
            @ptrCast(&socket_error),
            &error_len,
        );
        if (posix.errno(rc) != .SUCCESS or error_len != @sizeOf(@TypeOf(socket_error))) {
            return error.Unexpected;
        }
        if (socket_error == 0) return;
        return connectError(@enumFromInt(socket_error));
    }
}

fn setBlocking(socket_fd: posix.socket_t) net.IpAddress.ConnectError!void {
    const get_rc = posix.system.fcntl(socket_fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(get_rc) != .SUCCESS) return error.Unexpected;
    const nonblock = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    const set_rc = posix.system.fcntl(socket_fd, posix.F.SETFL, get_rc & ~nonblock);
    if (posix.errno(set_rc) != .SUCCESS) return error.Unexpected;
}

fn connectError(err: posix.E) net.IpAddress.ConnectError {
    return switch (err) {
        .ADDRNOTAVAIL => error.AddressUnavailable,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .AGAIN, .INPROGRESS => error.WouldBlock,
        .ALREADY => error.ConnectionPending,
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .HOSTUNREACH => error.HostUnreachable,
        .NETUNREACH => error.NetworkUnreachable,
        .TIMEDOUT => error.Timeout,
        .ACCES, .PERM => error.AccessDenied,
        .NETDOWN => error.NetworkDown,
        else => error.Unexpected,
    };
}

test "TCP connect deadline uses a nonblocking POSIX connection" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var threaded: Io.Threaded = .init(std.testing.allocator, .{
        .stack_size = 1024 * 1024,
        .concurrent_limit = .limited(2),
    });
    defer threaded.deinit();
    const io = threaded.io();

    var listen_address: net.IpAddress = .{ .ip4 = .loopback(0) };
    var listener = try listen_address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const deadline = Io.Clock.Timestamp.fromNow(io, .{
        .raw = Io.Duration.fromSeconds(1),
        .clock = .awake,
    });
    const stream = try connectTargetTimeout(.{ .address = listener.socket.address }, io, .{ .deadline = deadline });
    defer stream.close(io);

    const accepted = try listener.accept(io);
    accepted.close(io);
}

pub const OutboundConnection = union(enum) {
    plain: net.Stream,
    reality: reality.Client,

    pub fn initPlain(self: *OutboundConnection, stream: net.Stream) void {
        self.* = .{ .plain = stream };
    }

    pub fn initReality(self: *OutboundConnection, stream: net.Stream, settings: anytype, io: Io, deadline: ?Io.Clock.Timestamp) !void {
        self.* = .{ .reality = undefined };
        try self.reality.initDeadline(stream, settings, io, deadline);
    }

    pub fn close(self: *OutboundConnection, io: Io) void {
        switch (self.*) {
            .plain => |*stream| stream.close(io),
            .reality => |*client| client.close(io),
        }
    }

    pub fn writeAll(self: *OutboundConnection, bytes: []const u8, io: Io) !void {
        switch (self.*) {
            .plain => |stream| {
                var write_buffer: [16 * 1024]u8 = undefined;
                var writer = stream.writer(io, &write_buffer);
                try writer.interface.writeAll(bytes);
                try writer.interface.flush();
            },
            .reality => |*client| try client.writeAll(bytes),
        }
    }

    pub fn readSliceAll(self: *OutboundConnection, buffer: []u8, io: Io) !void {
        switch (self.*) {
            .plain => |stream| {
                var read_buffer: [16 * 1024]u8 = undefined;
                var reader = stream.reader(io, &read_buffer);
                try reader.interface.readSliceAll(buffer);
            },
            .reality => |*client| try client.readAll(buffer),
        }
    }

    pub fn read(self: *OutboundConnection, buffer: []u8, io: Io) !usize {
        switch (self.*) {
            .plain => |stream| {
                var read_buffer: [16 * 1024]u8 = undefined;
                var reader = stream.reader(io, &read_buffer);
                var slices = [_][]u8{buffer};
                return reader.interface.readVec(&slices) catch |err| switch (err) {
                    error.EndOfStream => 0,
                    else => |e| return e,
                };
            },
            .reality => |*client| return client.read(buffer),
        }
    }

    pub fn shutdownSend(self: *OutboundConnection, io: Io) void {
        switch (self.*) {
            .plain => |stream| stream.shutdown(io, .send) catch {},
            .reality => |*client| client.shutdownSend(io),
        }
    }

    pub fn enableDirectRead(self: *OutboundConnection) void {
        switch (self.*) {
            .plain => {},
            .reality => |*client| client.enableDirectRead(),
        }
    }

    pub fn enableDirectWrite(self: *OutboundConnection) void {
        switch (self.*) {
            .plain => {},
            .reality => |*client| client.enableDirectWrite(),
        }
    }

    pub fn flush(self: *OutboundConnection) !void {
        switch (self.*) {
            .plain => {},
            .reality => |*client| try client.flush(),
        }
    }

    pub fn pollStream(self: *OutboundConnection) net.Stream {
        return switch (self.*) {
            .plain => |stream| stream,
            .reality => |*client| client.stream,
        };
    }

    pub fn hasBufferedRead(self: *OutboundConnection) bool {
        return switch (self.*) {
            .plain => false,
            .reality => |*client| client.hasBufferedRead(),
        };
    }

    pub fn rawHandoffReady(self: *OutboundConnection) bool {
        return switch (self.*) {
            .plain => true,
            .reality => |*client| client.rawHandoffReady(),
        };
    }
};

pub fn writePreface(writer: *Io.Writer, preface: Preface) !void {
    if (preface.bytes.len == 0) return;
    try writer.writeAll(preface.bytes);
    try writer.flush();
}

pub fn bridge(client: net.Stream, upstream: net.Stream, io: Io) Io.Cancelable!void {
    var client_read_buffer: [16 * 1024]u8 = undefined;
    var client_reader = client.reader(io, &client_read_buffer);
    var client_write_buffer: [16 * 1024]u8 = undefined;
    var client_writer = client.writer(io, &client_write_buffer);

    var upstream_read_buffer: [16 * 1024]u8 = undefined;
    var upstream_reader = upstream.reader(io, &upstream_read_buffer);
    var upstream_write_buffer: [16 * 1024]u8 = undefined;
    var upstream_writer = upstream.writer(io, &upstream_write_buffer);

    var chunk: [16 * 1024]u8 = undefined;
    while (true) {
        const ready: Readable = if (client_reader.interface.buffered().len != 0 or
            upstream_reader.interface.buffered().len != 0)
            .{
                .first = client_reader.interface.buffered().len != 0,
                .second = upstream_reader.interface.buffered().len != 0,
            }
        else
            waitReadableTimeout(client, upstream, connection_idle_timeout_ms) catch return;
        if (ready.first and !copyOnce(&client_reader.interface, &upstream_writer.interface, &chunk)) return;
        if (ready.second and !copyOnce(&upstream_reader.interface, &client_writer.interface, &chunk)) return;
    }
}

pub const Readable = struct {
    first: bool,
    second: bool,
};

pub fn waitReadableTimeout(first: net.Stream, second: net.Stream, timeout_ms: i32) !Readable {
    var fds = [_]std.posix.pollfd{
        .{ .fd = first.socket.handle, .events = std.posix.POLL.IN, .revents = 0 },
        .{ .fd = second.socket.handle, .events = std.posix.POLL.IN, .revents = 0 },
    };
    const ready_count = try std.posix.poll(&fds, timeout_ms);
    if (ready_count == 0) return error.Timeout;
    const terminal = std.posix.POLL.ERR | std.posix.POLL.HUP | std.posix.POLL.NVAL;
    return .{
        .first = fds[0].revents & (std.posix.POLL.IN | terminal) != 0,
        .second = fds[1].revents & (std.posix.POLL.IN | terminal) != 0,
    };
}

fn copyOnce(reader: *Io.Reader, writer: *Io.Writer, chunk: []u8) bool {
    const n = readAvailable(reader, chunk) catch return false;
    if (n == 0) return false;
    writer.writeAll(chunk[0..n]) catch return false;
    writer.flush() catch return false;
    return true;
}

pub fn readAvailable(reader: *Io.Reader, destination: []u8) !usize {
    const buffered = reader.buffered();
    if (buffered.len != 0) {
        const n = @min(destination.len, buffered.len);
        @memcpy(destination[0..n], buffered[0..n]);
        reader.toss(n);
        return n;
    }

    var slices = [_][]u8{destination};
    return reader.readVec(&slices);
}

pub fn bridgeOutbound(client: net.Stream, upstream: *OutboundConnection, io: Io) Io.Cancelable!void {
    switch (upstream.*) {
        .plain => |stream| try bridge(client, stream, io),
        .reality => |*reality_client| {
            var client_read_buffer: [16 * 1024]u8 = undefined;
            var client_reader = client.reader(io, &client_read_buffer);
            var client_write_buffer: [16 * 1024]u8 = undefined;
            var client_writer = client.writer(io, &client_write_buffer);

            var chunk: [16 * 1024]u8 = undefined;
            while (true) {
                const ready: Readable = if (client_reader.interface.buffered().len != 0 or
                    reality_client.hasBufferedRead())
                    .{
                        .first = client_reader.interface.buffered().len != 0,
                        .second = reality_client.hasBufferedRead(),
                    }
                else
                    waitReadableTimeout(client, reality_client.stream, connection_idle_timeout_ms) catch return;
                if (ready.first) {
                    const n = readAvailable(&client_reader.interface, &chunk) catch return;
                    if (n == 0) return;
                    reality_client.writeAll(chunk[0..n]) catch return;
                    reality_client.flush() catch return;
                }
                if (ready.second) {
                    const n = reality_client.read(&chunk) catch |err| switch (err) {
                        error.ReadPending => continue,
                        else => return,
                    };
                    if (n == 0) return;
                    client_writer.interface.writeAll(chunk[0..n]) catch return;
                    client_writer.interface.flush() catch return;
                }
            }
        },
    }
}

test "creates host target from domain" {
    const target = try targetFromHostBytes("example.com", 443);
    switch (target) {
        .host => |host| {
            try std.testing.expectEqualStrings("example.com", host.name.bytes);
            try std.testing.expectEqual(@as(u16, 443), host.port);
        },
        .address => return error.ExpectedHost,
    }
}

test "creates address target from ip literal" {
    const target = try targetFromHostBytes("127.0.0.1", 80);
    switch (target) {
        .address => |address| {
            try std.testing.expectEqual(@as(u16, 80), address.getPort());
        },
        .host => return error.ExpectedAddress,
    }
}

test "readAvailable returns buffered bytes without filling destination" {
    const TrapReader = struct {
        interface: Io.Reader,
        storage: [8]u8,
        fill_called: bool,

        fn init(self: *@This()) void {
            self.storage = "buffered".*;
            self.fill_called = false;
            self.interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = &self.storage,
                .seek = 0,
                .end = self.storage.len,
            };
        }

        fn stream(reader: *Io.Reader, writer: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
            _ = writer;
            _ = limit;
            const self: *@This() = @alignCast(@fieldParentPtr("interface", reader));
            self.fill_called = true;
            return error.ReadFailed;
        }
    };

    var reader: TrapReader = undefined;
    reader.init();
    var destination: [32]u8 = undefined;

    const n = try readAvailable(&reader.interface, &destination);

    try std.testing.expectEqual(@as(usize, 8), n);
    try std.testing.expectEqualStrings("buffered", destination[0..n]);
    try std.testing.expect(!reader.fill_called);
}
