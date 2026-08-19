const std = @import("std");
const Io = std.Io;
const net = Io.net;

/// A stable logical UDP association. `flow_id` remains unchanged until the
/// TUN flow expires, so an outbound can retain one kernel socket or one proxy
/// stream without depending on the packet codec's private key type.
pub const Session = struct {
    flow_id: u64,
    target: net.IpAddress,
    inbound_tag: ?[]const u8 = null,
    outbound_tag: ?[]const u8 = null,
};

pub const ResponseSink = struct {
    context: *anyopaque,
    send_fn: *const fn (*anyopaque, net.IpAddress, []const u8, Io) anyerror!void,

    /// `source` is the actual peer that produced the response. A fixed-target
    /// outbound normally passes `Session.target`; cone-style outbounds may
    /// report another peer and let the TUN layer decide whether to accept it.
    pub fn send(self: ResponseSink, source: net.IpAddress, payload: []const u8, io: Io) !void {
        try self.send_fn(self.context, source, payload, io);
    }
};

pub const CloseReason = enum {
    idle_timeout,
    dispatch_failed,
    shutdown,
};

/// Datagram dispatch is deliberately separate from the TCP Dispatcher. Calls
/// for one flow must be serialized by the caller. The response sink is borrowed
/// and may only be used before `dispatch_fn` returns; it may be called zero or
/// more times. Outbounds retain association state keyed by `Session.flow_id`
/// and release it in `close_fn`.
pub const Dispatcher = struct {
    context: *anyopaque,
    dispatch_fn: *const fn (*anyopaque, Session, []const u8, ResponseSink, Io) anyerror!void,
    close_fn: *const fn (*anyopaque, u64, CloseReason, Io) void,

    pub fn dispatch(
        self: Dispatcher,
        sess: Session,
        payload: []const u8,
        response_sink: ResponseSink,
        io: Io,
    ) !void {
        try self.dispatch_fn(self.context, sess, payload, response_sink, io);
    }

    pub fn close(self: Dispatcher, flow_id: u64, reason: CloseReason, io: Io) void {
        self.close_fn(self.context, flow_id, reason, io);
    }
};

test "datagram dispatcher preserves flow identity and response boundaries" {
    const Harness = struct {
        dispatched_flow: u64 = 0,
        response_count: usize = 0,

        fn dispatch(
            context: *anyopaque,
            sess: Session,
            payload: []const u8,
            sink: ResponseSink,
            io: Io,
        ) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.dispatched_flow = sess.flow_id;
            try sink.send(sess.target, payload, io);
        }

        fn close(_: *anyopaque, _: u64, _: CloseReason, _: Io) void {}

        fn response(context: *anyopaque, _: net.IpAddress, payload: []const u8, _: Io) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            try std.testing.expectEqualStrings("one datagram", payload);
            self.response_count += 1;
        }
    };

    var harness: Harness = .{};
    const dispatcher: Dispatcher = .{
        .context = &harness,
        .dispatch_fn = Harness.dispatch,
        .close_fn = Harness.close,
    };
    const sink: ResponseSink = .{ .context = &harness, .send_fn = Harness.response };
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    try dispatcher.dispatch(.{
        .flow_id = 42,
        .target = .{ .ip4 = .{ .bytes = .{ 192, 0, 2, 1 }, .port = 53 } },
    }, "one datagram", sink, threaded.io());
    try std.testing.expectEqual(@as(u64, 42), harness.dispatched_flow);
    try std.testing.expectEqual(@as(usize, 1), harness.response_count);
}
