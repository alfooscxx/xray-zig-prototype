const std = @import("std");
const Io = std.Io;
const net = Io.net;

const datagram = @import("../../net/datagram.zig");

pub const max_datagram_size = 65535;

/// One stable direct UDP association. The socket is bound once and therefore
/// preserves its source port across all datagrams in the TUN flow.
pub const Association = struct {
    socket: net.Socket,
    target: net.IpAddress,

    pub fn init(target: net.IpAddress, io: Io) !Association {
        const local: net.IpAddress = switch (target) {
            .ip4 => .{ .ip4 = .unspecified(0) },
            .ip6 => .{ .ip6 = .unspecified(0) },
        };
        return .{
            .socket = try local.bind(io, .{ .mode = .dgram, .protocol = .udp }),
            .target = target,
        };
    }

    pub fn close(self: *Association, io: Io) void {
        self.socket.close(io);
        self.* = undefined;
    }

    pub fn send(self: *Association, payload: []const u8, io: Io) !void {
        try self.socket.send(io, &self.target, payload);
    }

    pub fn receive(
        self: *Association,
        buffer: []u8,
        timeout: Io.Timeout,
        io: Io,
    ) !net.IncomingMessage {
        const message = try self.socket.receiveTimeout(io, buffer, timeout);
        if (message.flags.trunc) return error.DatagramTruncated;
        return message;
    }
};

/// A minimal synchronous adapter for `datagram.Dispatcher`. It is useful for
/// initial TUN integration and tests: every dispatch sends one datagram and
/// waits for at most one response. Production integration should drive
/// `Association.receive` in a dedicated per-flow pump so unsolicited and
/// multiple responses are not delayed by the next uplink packet.
pub const Dispatcher = struct {
    allocator: std.mem.Allocator,
    associations: std.AutoHashMap(u64, *Association),
    response_timeout: Io.Clock.Duration,

    pub fn init(allocator: std.mem.Allocator, response_timeout: Io.Clock.Duration) Dispatcher {
        return .{
            .allocator = allocator,
            .associations = std.AutoHashMap(u64, *Association).init(allocator),
            .response_timeout = response_timeout,
        };
    }

    pub fn deinit(self: *Dispatcher, io: Io) void {
        var iterator = self.associations.valueIterator();
        while (iterator.next()) |association| {
            association.*.close(io);
            self.allocator.destroy(association.*);
        }
        self.associations.deinit();
        self.* = undefined;
    }

    pub fn interface(self: *Dispatcher) datagram.Dispatcher {
        return .{
            .context = self,
            .dispatch_fn = dispatch,
            .close_fn = closeFlow,
        };
    }

    fn dispatch(
        context: *anyopaque,
        sess: datagram.Session,
        payload: []const u8,
        response_sink: datagram.ResponseSink,
        io: Io,
    ) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const association = try self.getOrCreate(sess.flow_id, sess.target, io);
        if (!association.target.eql(&sess.target)) return error.UdpFlowTargetChanged;
        try association.send(payload, io);

        var buffer: [max_datagram_size]u8 = undefined;
        const message = association.receive(&buffer, .{ .duration = self.response_timeout }, io) catch |err| switch (err) {
            error.Timeout => return,
            else => |e| return e,
        };
        try response_sink.send(message.from, message.data, io);
    }

    fn closeFlow(
        context: *anyopaque,
        flow_id: u64,
        _: datagram.CloseReason,
        io: Io,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        const removed = self.associations.fetchRemove(flow_id) orelse return;
        removed.value.close(io);
        self.allocator.destroy(removed.value);
    }

    fn getOrCreate(
        self: *Dispatcher,
        flow_id: u64,
        target: net.IpAddress,
        io: Io,
    ) !*Association {
        if (self.associations.get(flow_id)) |association| return association;
        const association = try self.allocator.create(Association);
        errdefer self.allocator.destroy(association);
        association.* = try Association.init(target, io);
        errdefer association.close(io);
        try self.associations.put(flow_id, association);
        return association;
    }
};

test "direct UDP association preserves source port" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{
        .stack_size = 1024 * 1024,
        .concurrent_limit = .limited(2),
    });
    defer threaded.deinit();
    const io = threaded.io();

    const bind_address: net.IpAddress = .{ .ip4 = .loopback(0) };
    const server = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer server.close(io);
    var association = try Association.init(server.address, io);
    defer association.close(io);

    try association.send("first", io);
    var server_buffer: [64]u8 = undefined;
    const first = try server.receive(io, &server_buffer);
    try std.testing.expectEqualStrings("first", first.data);
    const source = first.from;

    try association.send("second", io);
    const second = try server.receive(io, &server_buffer);
    try std.testing.expectEqualStrings("second", second.data);
    try std.testing.expect(source.eql(&second.from));
}
