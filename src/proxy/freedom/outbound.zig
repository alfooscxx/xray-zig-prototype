const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const dns_client = @import("../../dns/client.zig");
const log = @import("../../log.zig");
const monitoring = @import("../../monitoring.zig");
const session = @import("../../net/session.zig");
const sockhash = @import("../sk_lookup/sockhash.zig");

const HandoffOutcome = union(enum) {
    offloaded,
    hybrid_raw: sockhash.FallbackReason,
    raw_fallback: sockhash.FallbackReason,
    raw_failure: struct {
        reason: sockhash.FallbackReason,
        cause: anyerror,
    },
    terminal: sockhash.FallbackReason,
};

const HandoffOps = struct {
    context: *anyopaque,
    admit_fn: *const fn (*anyopaque, net.Stream, net.Stream) sockhash.Admission,
    adopt_raw_fn: *const fn (*anyopaque, net.Stream, net.Stream) anyerror!void,

    fn admit(self: HandoffOps, client: net.Stream, upstream: net.Stream) sockhash.Admission {
        return self.admit_fn(self.context, client, upstream);
    }

    fn adoptRaw(self: HandoffOps, client: net.Stream, upstream: net.Stream) !void {
        try self.adopt_raw_fn(self.context, client, upstream);
    }
};

const LiveHandoff = struct {
    manager: *sockhash.Manager,
    reactor: *session.RawReactor,

    fn ops(self: *LiveHandoff) HandoffOps {
        return .{
            .context = self,
            .admit_fn = admit,
            .adopt_raw_fn = adoptRaw,
        };
    }

    fn admit(context: *anyopaque, client: net.Stream, upstream: net.Stream) sockhash.Admission {
        const self: *LiveHandoff = @ptrCast(@alignCast(context));
        return self.manager.admitOwned(client, upstream, self.reactor, .freedom);
    }

    fn adoptRaw(context: *anyopaque, client: net.Stream, upstream: net.Stream) !void {
        const self: *LiveHandoff = @ptrCast(@alignCast(context));
        try self.reactor.adoptDuplicate(client, upstream);
    }
};

pub fn handle(
    client: net.Stream,
    sess: session.Session,
    preface: session.Preface,
    dns_config: ?config.DnsConfig,
    dispatcher: session.Dispatcher,
    raw_reactor: *session.RawReactor,
    sockhash_manager: ?*sockhash.Manager,
    io: Io,
) !void {
    const upstream = switch (sess.target) {
        .address => try session.connectTarget(sess.target, io),
        .host => |host| if (dns_config) |cfg|
            try dns_client.connect(host, sess.preferred_family, cfg, dispatcher, io)
        else
            try session.connectTarget(sess.target, io),
    };
    defer upstream.close(io);

    // The authorized sk_lookup inbound always supplies an empty preface. Keep
    // that path free of userspace writer state so cutover can happen directly
    // after connect/resolve. A non-empty preface is a generic freedom session
    // and remains in userspace even if a caller accidentally marks it eligible.
    if (canAttemptSockhash(sockhash_manager != null, preface.bytes.len)) {
        var live: LiveHandoff = .{ .manager = sockhash_manager.?, .reactor = raw_reactor };
        const outcome = completeHandoff(live.ops(), client, upstream);
        logHandoff(outcome);
        if (outcome == .raw_failure) return outcome.raw_failure.cause;
        return;
    }
    if (sockhash_manager != null) {
        monitoring.registry.offload(.freedom, .raw_fallback, .nonempty_preface, nowNs(io));
        log.warn("freedom sockhash admission skipped (nonempty-preface); using raw reactor\n", .{});
    }

    if (preface.bytes.len != 0) {
        var write_buffer: [4096]u8 = undefined;
        var writer = upstream.writer(io, &write_buffer);
        try session.writePreface(&writer.interface, preface);
        try writer.interface.flush();
    }
    try raw_reactor.adoptDuplicate(client, upstream);
}

fn nowNs(io: Io) u64 {
    const value = Io.Timestamp.now(io, .awake).nanoseconds;
    return if (value > 0) @intCast(value) else 0;
}

fn canAttemptSockhash(manager_available: bool, preface_len: usize) bool {
    return manager_available and preface_len == 0;
}

fn completeHandoff(ops: HandoffOps, client: net.Stream, upstream: net.Stream) HandoffOutcome {
    return switch (ops.admit(client, upstream)) {
        .offloaded => .offloaded,
        .hybrid_raw => |reason| .{ .hybrid_raw = reason },
        .fallback => |reason| outcome: {
            ops.adoptRaw(client, upstream) catch |err| break :outcome .{ .raw_failure = .{
                .reason = reason,
                .cause = err,
            } };
            break :outcome .{ .raw_fallback = reason };
        },
        .terminal => |reason| .{ .terminal = reason },
    };
}

fn logHandoff(outcome: HandoffOutcome) void {
    switch (outcome) {
        .offloaded => log.info("freedom sockhash-handoff\n", .{}),
        .hybrid_raw => |reason| log.warn(
            "freedom sockhash partial admission ({s}); hybrid raw fallback\n",
            .{@tagName(reason)},
        ),
        .raw_fallback => |reason| log.warn(
            "freedom sockhash admission fallback ({s}); raw-reactor-handoff\n",
            .{@tagName(reason)},
        ),
        .raw_failure => |failure| log.warn(
            "freedom sockhash admission fallback ({s}); raw-reactor-handoff failed ({s})\n",
            .{ @tagName(failure.reason), @errorName(failure.cause) },
        ),
        .terminal => |reason| log.warn(
            "freedom sockhash cutover failed closed ({s})\n",
            .{@tagName(reason)},
        ),
    }
}

const TestHandoff = struct {
    admission: sockhash.Admission,
    admit_count: usize = 0,
    raw_count: usize = 0,
    fail_raw: bool = false,

    fn ops(self: *TestHandoff) HandoffOps {
        return .{
            .context = self,
            .admit_fn = admit,
            .adopt_raw_fn = adoptRaw,
        };
    }

    fn admit(context: *anyopaque, _: net.Stream, _: net.Stream) sockhash.Admission {
        const self: *TestHandoff = @ptrCast(@alignCast(context));
        self.admit_count += 1;
        return self.admission;
    }

    fn adoptRaw(context: *anyopaque, _: net.Stream, _: net.Stream) !void {
        const self: *TestHandoff = @ptrCast(@alignCast(context));
        self.raw_count += 1;
        if (self.fail_raw) return error.TestRawAdmissionFailed;
    }
};

fn testStream() net.Stream {
    return .{ .socket = .{
        .handle = -1,
        .address = net.IpAddress.parse("127.0.0.1", 1) catch unreachable,
    } };
}

test "freedom full SOCKHASH admission bypasses the raw reactor" {
    var backend: TestHandoff = .{ .admission = .offloaded };
    const outcome = completeHandoff(backend.ops(), testStream(), testStream());
    try std.testing.expect(outcome == .offloaded);
    try std.testing.expectEqual(@as(usize, 1), backend.admit_count);
    try std.testing.expectEqual(@as(usize, 0), backend.raw_count);
}

test "freedom SOCKHASH eligibility requires the empty sk_lookup preface" {
    try std.testing.expect(canAttemptSockhash(true, 0));
    try std.testing.expect(!canAttemptSockhash(false, 0));
    try std.testing.expect(!canAttemptSockhash(true, 1));
}

test "freedom ordinary SOCKHASH failure falls back exactly once" {
    var backend: TestHandoff = .{ .admission = .{ .fallback = .capacity } };
    const outcome = completeHandoff(backend.ops(), testStream(), testStream());
    try std.testing.expect(outcome == .raw_fallback);
    try std.testing.expectEqual(@as(usize, 1), backend.admit_count);
    try std.testing.expectEqual(@as(usize, 1), backend.raw_count);
}

test "freedom partial and terminal admissions never start a second raw owner" {
    var hybrid: TestHandoff = .{ .admission = .{ .hybrid_raw = .upstream_source } };
    const hybrid_outcome = completeHandoff(hybrid.ops(), testStream(), testStream());
    try std.testing.expect(hybrid_outcome == .hybrid_raw);
    try std.testing.expectEqual(@as(usize, 0), hybrid.raw_count);

    var terminal: TestHandoff = .{ .admission = .{ .terminal = .upstream_kick_payload } };
    const terminal_outcome = completeHandoff(terminal.ops(), testStream(), testStream());
    try std.testing.expect(terminal_outcome == .terminal);
    try std.testing.expectEqual(@as(usize, 0), terminal.raw_count);
}

test "freedom reports a raw-reactor failure without retrying ownership" {
    var backend: TestHandoff = .{
        .admission = .{ .fallback = .duplicate },
        .fail_raw = true,
    };
    const outcome = completeHandoff(backend.ops(), testStream(), testStream());
    try std.testing.expect(outcome == .raw_failure);
    try std.testing.expectEqual(error.TestRawAdmissionFailed, outcome.raw_failure.cause);
    try std.testing.expectEqual(@as(usize, 1), backend.admit_count);
    try std.testing.expectEqual(@as(usize, 1), backend.raw_count);
}
