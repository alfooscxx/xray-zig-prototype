const std = @import("std");
const Io = std.Io;
const net = Io.net;

const xray = @import("xray_zig");
const session = xray.net.session;
const sockhash = xray.proxy.sk_lookup.sockhash;

const timeout_ms = 10_000;

const Pair = struct {
    outside: net.Stream,
    inside: net.Stream,
};

pub fn main(init: std.process.Init) !void {
    var threaded: Io.Threaded = .init(init.gpa, .{
        .stack_size = 256 * 1024,
        .concurrent_limit = .limited(16),
    });
    defer threaded.deinit();
    const io = threaded.io();

    var manager = try sockhash.Manager.init(std.heap.page_allocator, io, 4, 30);
    defer manager.deinit();
    var reactor = try session.RawReactor.init(std.heap.page_allocator, io, 4);
    defer reactor.deinit();

    var group: Io.Group = .init;
    defer {
        manager.stop();
        reactor.stop();
        group.cancel(io);
    }
    try group.concurrent(io, runManager, .{&manager});
    try group.concurrent(io, runReactor, .{&reactor});

    try testPrequeuedOrderingAndHalfClose(&manager, &reactor, io);
    try testPreAdmissionClientHalfClose(&manager, &reactor, io);
    try testPreAdmissionUpstreamHalfClose(&manager, &reactor, io);
    try testResetPropagation(&manager, &reactor, io);

    var stdout_buffer: [128]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.writeAll("PASS: SOCKHASH prequeue/order/pre-admission-half-close/reset capability selftest\n");
    try stdout_writer.interface.flush();
}

fn testPreAdmissionClientHalfClose(
    manager: *sockhash.Manager,
    reactor: *session.RawReactor,
    io: Io,
) !void {
    const client = try tcpPair(io);
    defer client.outside.close(io);
    const upstream = try tcpPair(io);
    defer upstream.outside.close(io);

    try writeAll(client.outside, "request-before-client-fin", io);
    try client.outside.shutdown(io, .send);
    switch (manager.admitOwned(client.inside, upstream.inside, reactor, .freedom)) {
        .offloaded => {},
        else => return error.SockhashAdmissionFailed,
    }
    client.inside.close(io);
    upstream.inside.close(io);

    try expectBytes(upstream.outside, "request-before-client-fin", io);
    try expectEof(upstream.outside, io);
    try writeAll(upstream.outside, "response-after-client-fin", io);
    try expectBytes(client.outside, "response-after-client-fin", io);
    try upstream.outside.shutdown(io, .send);
    try expectEof(client.outside, io);
}

fn testPreAdmissionUpstreamHalfClose(
    manager: *sockhash.Manager,
    reactor: *session.RawReactor,
    io: Io,
) !void {
    const client = try tcpPair(io);
    defer client.outside.close(io);
    const upstream = try tcpPair(io);
    defer upstream.outside.close(io);

    try writeAll(upstream.outside, "response-before-upstream-fin", io);
    try upstream.outside.shutdown(io, .send);
    switch (manager.admitOwned(client.inside, upstream.inside, reactor, .freedom)) {
        .offloaded => {},
        else => return error.SockhashAdmissionFailed,
    }
    client.inside.close(io);
    upstream.inside.close(io);

    try expectBytes(client.outside, "response-before-upstream-fin", io);
    try expectEof(client.outside, io);
    try writeAll(client.outside, "request-after-upstream-fin", io);
    try expectBytes(upstream.outside, "request-after-upstream-fin", io);
    try client.outside.shutdown(io, .send);
    try expectEof(upstream.outside, io);
}

fn runManager(manager: *sockhash.Manager) Io.Cancelable!void {
    try manager.run();
}

fn runReactor(reactor: *session.RawReactor) Io.Cancelable!void {
    reactor.run() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => std.debug.panic("raw io_uring reactor stopped: {s}", .{@errorName(err)}),
    };
}

fn testPrequeuedOrderingAndHalfClose(
    manager: *sockhash.Manager,
    reactor: *session.RawReactor,
    io: Io,
) !void {
    const client = try tcpPair(io);
    defer client.outside.close(io);
    const upstream = try tcpPair(io);
    defer upstream.outside.close(io);

    try writeAll(client.outside, "client-prequeued-", io);
    try writeAll(upstream.outside, "upstream-prequeued-", io);
    switch (manager.admit(client.inside, upstream.inside, reactor)) {
        .offloaded => {},
        else => return error.SockhashAdmissionFailed,
    }
    client.inside.close(io);
    upstream.inside.close(io);

    try writeAll(client.outside, "client-post", io);
    try writeAll(upstream.outside, "upstream-post", io);
    try expectBytes(upstream.outside, "client-prequeued-client-post", io);
    try expectBytes(client.outside, "upstream-prequeued-upstream-post", io);

    try client.outside.shutdown(io, .send);
    try expectEof(upstream.outside, io);
    try writeAll(upstream.outside, "response-after-client-fin", io);
    try expectBytes(client.outside, "response-after-client-fin", io);
    try upstream.outside.shutdown(io, .send);
    try expectEof(client.outside, io);
}

fn testResetPropagation(
    manager: *sockhash.Manager,
    reactor: *session.RawReactor,
    io: Io,
) !void {
    const client = try tcpPair(io);
    const upstream = try tcpPair(io);
    defer upstream.outside.close(io);
    switch (manager.admit(client.inside, upstream.inside, reactor)) {
        .offloaded => {},
        else => return error.SockhashAdmissionFailed,
    }
    client.inside.close(io);
    upstream.inside.close(io);

    resetClose(client.outside);
    try expectReset(upstream.outside);
}

fn tcpPair(io: Io) !Pair {
    var address = try net.IpAddress.parse("127.0.0.1", 0);
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const outside = try listener.socket.address.connect(io, .{ .mode = .stream, .protocol = .tcp });
    errdefer outside.close(io);
    return .{ .outside = outside, .inside = try listener.accept(io) };
}

fn writeAll(stream: net.Stream, bytes: []const u8, io: Io) !void {
    var buffer: [4096]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

fn expectBytes(stream: net.Stream, expected: []const u8, io: Io) !void {
    const ready = try session.waitReadableTimeout(stream, stream, timeout_ms);
    if (!ready.first) return error.SockhashReadTimeout;
    var buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &buffer);
    var actual: [256]u8 = undefined;
    if (expected.len > actual.len) return error.TestPayloadTooLarge;
    try reader.interface.readSliceAll(actual[0..expected.len]);
    if (!std.mem.eql(u8, expected, actual[0..expected.len])) return error.SockhashOrderingMismatch;
}

fn expectEof(stream: net.Stream, io: Io) !void {
    const ready = try session.waitReadableTimeout(stream, stream, timeout_ms);
    if (!ready.first) return error.SockhashReadTimeout;
    var buffer: [16]u8 = undefined;
    var reader = stream.reader(io, &buffer);
    var output: [1]u8 = undefined;
    var slices = [_][]u8{&output};
    _ = reader.interface.readVec(&slices) catch |err| switch (err) {
        error.EndOfStream => return,
        else => return err,
    };
    return error.ExpectedEndOfStream;
}

fn resetClose(stream: net.Stream) void {
    const linux = std.os.linux;
    const linger: linux.linger = .{ .onoff = 1, .linger = 0 };
    _ = linux.setsockopt(
        stream.socket.handle,
        linux.SOL.SOCKET,
        linux.SO.LINGER,
        @ptrCast(&linger),
        @sizeOf(linux.linger),
    );
    _ = linux.close(stream.socket.handle);
}

fn expectReset(stream: net.Stream) !void {
    const linux = std.os.linux;
    var fds = [_]std.posix.pollfd{.{
        .fd = stream.socket.handle,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const ready = try std.posix.poll(&fds, timeout_ms);
    if (ready == 0) return error.SockhashResetTimeout;
    var byte: [1]u8 = undefined;
    const rc = linux.recvfrom(stream.socket.handle, &byte, byte.len, linux.MSG.DONTWAIT, null, null);
    return switch (linux.errno(rc)) {
        .CONNRESET => {},
        else => error.ExpectedConnectionReset,
    };
}
