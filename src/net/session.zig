const std = @import("std");
const Io = std.Io;
const net = Io.net;

const reality = @import("../transport/reality/client.zig");
pub const RawReactor = @import("reactor.zig").Reactor;

pub const max_preface_len = 2048;
pub const response_header_timeout_ms = 60 * 1000;
pub const connection_idle_timeout_ms = 300 * 1000;

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
    return connectTarget(try targetFromHostBytes(host, port), io);
}

pub fn connectTarget(target: Target, io: Io) !net.Stream {
    const options: net.IpAddress.ConnectOptions = .{
        .mode = .stream,
        .protocol = .tcp,
    };

    return switch (target) {
        .address => |address| address.connect(io, options),
        .host => |host| host.name.connect(io, host.port, options),
    };
}

pub const OutboundConnection = union(enum) {
    plain: net.Stream,
    reality: reality.Client,

    pub fn initPlain(self: *OutboundConnection, stream: net.Stream) void {
        self.* = .{ .plain = stream };
    }

    pub fn initReality(self: *OutboundConnection, stream: net.Stream, settings: anytype, io: Io) !void {
        self.* = .{ .reality = undefined };
        try self.reality.init(stream, settings, io);
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
