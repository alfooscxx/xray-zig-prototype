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

const BridgePath = enum { sockhash, raw };

pub fn main(init: std.process.Init) !void {
    var threaded: Io.Threaded = .init(init.gpa, .{
        .stack_size = 256 * 1024,
        .concurrent_limit = .limited(16),
    });
    defer threaded.deinit();
    const io = threaded.io();

    var reactor = try session.RawReactor.init(std.heap.page_allocator, io, 4);
    defer reactor.deinit();

    var group: Io.Group = .init;
    defer {
        reactor.stop();
        group.cancel(io);
    }
    try group.concurrent(io, runReactor, .{&reactor});

    try testBackpressureIsIsolatedPerFlow(&reactor, io);

    var manager = try sockhash.Manager.init(std.heap.page_allocator, io, 4, 30);
    defer manager.deinit();
    defer manager.stop();
    try group.concurrent(io, runManager, .{&manager});

    try testPrequeuedOrderingAndHalfClose(&manager, &reactor, io);
    try testPreAdmissionClientHalfClose(&manager, &reactor, io);
    try testPreAdmissionUpstreamHalfClose(&manager, &reactor, io);
    try testResetPropagation(&manager, &reactor, io);
    try testStalledDestinationAppliesBackpressure(&manager, &reactor, io);

    var stdout_buffer: [128]u8 = undefined;
    var stdout_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    try stdout_writer.interface.writeAll("PASS: SOCKHASH prequeue/order/half-close/reset/per-flow-backpressure capability selftest\n");
    try stdout_writer.interface.flush();
}

fn testBackpressureIsIsolatedPerFlow(reactor: *session.RawReactor, io: Io) !void {
    // Keep this manager stopped while generating the condition. That makes the
    // test deterministic: userspace cannot close the stalled flow and return
    // its credit before the healthy packet reaches the verdict program.
    var manager = try sockhash.Manager.init(std.heap.page_allocator, io, 2, 30);
    defer manager.deinit();

    const stalled_client = try tcpPair(io);
    defer stalled_client.outside.close(io);
    const stalled_upstream = try tcpPair(io);
    defer stalled_upstream.outside.close(io);
    const healthy_client = try tcpPair(io);
    defer healthy_client.outside.close(io);
    const healthy_upstream = try tcpPair(io);
    defer healthy_upstream.outside.close(io);

    try setSocketBuffer(stalled_client.outside.socket.handle, std.posix.SO.RCVBUF, 64 * 1024);
    try setSocketBuffer(stalled_client.inside.socket.handle, std.posix.SO.SNDBUF, 64 * 1024);
    try setSocketBuffer(stalled_upstream.inside.socket.handle, std.posix.SO.RCVBUF, 64 * 1024);
    try setSocketBuffer(stalled_upstream.outside.socket.handle, std.posix.SO.SNDBUF, 64 * 1024);

    try expectOffloaded(
        manager.admitOwned(stalled_client.inside, stalled_upstream.inside, reactor, .freedom),
        "per-flow-backpressure-stalled",
        io,
    );
    stalled_client.inside.close(io);
    stalled_upstream.inside.close(io);
    try expectOffloaded(
        manager.admitOwned(healthy_client.inside, healthy_upstream.inside, reactor, .freedom),
        "per-flow-backpressure-healthy",
        io,
    );
    healthy_client.inside.close(io);
    healthy_upstream.inside.close(io);

    try fillUntilBackpressure(stalled_upstream.outside);

    const marker = "healthy-flow-survives";
    try writeAll(healthy_upstream.outside, marker, io);
    const ready = try session.waitReadableTimeout(healthy_client.outside, healthy_client.outside, 1000);
    if (!ready.first) return error.SockhashBackpressureAffectedHealthyFlow;
    try expectBytes(healthy_client.outside, marker, io);
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
    _ = try admitHalfClosedOrRaw(
        manager,
        reactor,
        client.inside,
        upstream.inside,
        .client_target_prepare,
        "pre-admission-client-half-close",
        io,
    );
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
    _ = try admitHalfClosedOrRaw(
        manager,
        reactor,
        client.inside,
        upstream.inside,
        .upstream_target_prepare,
        "pre-admission-upstream-half-close",
        io,
    );
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
    try expectOffloaded(
        manager.admit(client.inside, upstream.inside, reactor),
        "prequeued-ordering-and-half-close",
        io,
    );
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
    try expectOffloaded(manager.admit(client.inside, upstream.inside, reactor), "reset-propagation", io);
    client.inside.close(io);
    upstream.inside.close(io);

    resetClose(client.outside);
    try expectReset(upstream.outside);
}

fn testStalledDestinationAppliesBackpressure(
    manager: *sockhash.Manager,
    reactor: *session.RawReactor,
    io: Io,
) !void {
    const client = try tcpPair(io);
    defer client.outside.close(io);
    const upstream = try tcpPair(io);
    defer upstream.outside.close(io);

    try setSocketBuffer(client.outside.socket.handle, std.posix.SO.RCVBUF, 64 * 1024);
    try setSocketBuffer(client.inside.socket.handle, std.posix.SO.SNDBUF, 64 * 1024);
    try setSocketBuffer(upstream.inside.socket.handle, std.posix.SO.RCVBUF, 64 * 1024);
    try setSocketBuffer(upstream.outside.socket.handle, std.posix.SO.SNDBUF, 64 * 1024);

    try expectOffloaded(
        manager.admitOwned(client.inside, upstream.inside, reactor, .freedom),
        "stalled-destination-backpressure",
        io,
    );
    client.inside.close(io);
    upstream.inside.close(io);

    // Do not read client.outside. A bounded bridge must stop accepting data
    // from upstream once the destination send window and its bounded pending
    // storage are full. The current SK_SKB redirect path instead ACKs the
    // source and can enqueue all of this in sk_psock.ingress_skb.
    try fillUntilBackpressure(upstream.outside);
}

fn fillUntilBackpressure(source: net.Stream) !void {
    const acceptance_limit = 8 * 1024 * 1024;
    var payload: [64 * 1024]u8 = @splat(0xa5);
    var accepted: usize = 0;
    send_loop: while (accepted < acceptance_limit) {
        const remaining = acceptance_limit - accepted;
        const chunk = payload[0..@min(payload.len, remaining)];
        const rc = std.os.linux.sendto(
            source.socket.handle,
            chunk.ptr,
            chunk.len,
            std.os.linux.MSG.DONTWAIT | std.os.linux.MSG.NOSIGNAL,
            null,
            0,
        );
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => accepted += rc,
            .AGAIN => {
                var descriptors = [1]std.posix.pollfd{.{
                    .fd = source.socket.handle,
                    .events = std.posix.POLL.OUT,
                    .revents = 0,
                }};
                const ready = try std.posix.poll(&descriptors, 500);
                if (ready == 0) break :send_loop;
            },
            .CONNRESET, .PIPE => break,
            .INTR => continue,
            else => return error.SockhashBackpressureSendFailed,
        }
    }
    if (accepted == acceptance_limit) return error.SockhashBackpressureUnbounded;
}

fn expectOffloaded(admission: sockhash.Admission, stage: []const u8, io: Io) !void {
    switch (admission) {
        .offloaded => return,
        .fallback => |reason| {
            try reportAdmissionFailure(stage, "fallback", reason, io);
            return error.SockhashAdmissionFallback;
        },
        .hybrid_raw => |reason| {
            try reportAdmissionFailure(stage, "hybrid_raw", reason, io);
            return error.SockhashAdmissionHybridRaw;
        },
        .terminal => |reason| {
            try reportAdmissionFailure(stage, "terminal", reason, io);
            return error.SockhashAdmissionTerminal;
        },
    }
}

fn admitHalfClosedOrRaw(
    manager: *sockhash.Manager,
    reactor: *session.RawReactor,
    client: net.Stream,
    upstream: net.Stream,
    expected_fallback: sockhash.FallbackReason,
    stage: []const u8,
    io: Io,
) !BridgePath {
    switch (manager.admitOwned(client, upstream, reactor, .freedom)) {
        .offloaded => return .sockhash,
        .fallback => |reason| {
            if (reason != expected_fallback) {
                try reportAdmissionFailure(stage, "fallback", reason, io);
                return error.UnexpectedSockhashHalfCloseFallback;
            }
            try reportExpectedFallback(stage, reason, io);
            try reactor.adoptDuplicate(client, upstream);
            return .raw;
        },
        .hybrid_raw => |reason| {
            try reportAdmissionFailure(stage, "hybrid_raw", reason, io);
            return error.UnexpectedSockhashHalfCloseHybridRaw;
        },
        .terminal => |reason| {
            try reportAdmissionFailure(stage, "terminal", reason, io);
            return error.UnexpectedSockhashHalfCloseTerminal;
        },
    }
}

fn reportExpectedFallback(stage: []const u8, reason: sockhash.FallbackReason, io: Io) !void {
    var stderr_buffer: [256]u8 = undefined;
    var stderr_writer: Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    try stderr_writer.interface.print(
        "INFO: SOCKHASH admission stage={s} expected_fallback={s} path=raw_reactor\n",
        .{ stage, @tagName(reason) },
    );
    try stderr_writer.interface.flush();
}

fn reportAdmissionFailure(stage: []const u8, variant: []const u8, reason: sockhash.FallbackReason, io: Io) !void {
    var stderr_buffer: [256]u8 = undefined;
    var stderr_writer: Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    try stderr_writer.interface.print(
        "FAIL: SOCKHASH admission stage={s} variant={s} reason={s}\n",
        .{ stage, variant, @tagName(reason) },
    );
    try stderr_writer.interface.flush();
}

fn setSocketBuffer(fd: std.posix.fd_t, option: u32, value: c_int) !void {
    const rc = std.os.linux.setsockopt(
        fd,
        std.os.linux.SOL.SOCKET,
        option,
        @ptrCast(&value),
        @sizeOf(c_int),
    );
    if (std.os.linux.errno(rc) != .SUCCESS) return error.SetSocketBufferFailed;
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
