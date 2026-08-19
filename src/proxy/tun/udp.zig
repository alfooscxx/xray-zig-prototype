const std = @import("std");
const Io = std.Io;
const net = Io.net;

const datagram = @import("../../net/datagram.zig");
pub const packet = @import("udp_packet.zig");

pub const PacketSink = struct {
    context: *anyopaque,
    write_fn: *const fn (*anyopaque, []const u8, Io) anyerror!void,

    pub fn write(self: PacketSink, bytes: []const u8, io: Io) !void {
        try self.write_fn(self.context, bytes, io);
    }
};

pub const Options = struct {
    max_flows: usize = 256,
    idle_timeout_ns: u64 = 60 * std.time.ns_per_s,
};

const Flow = struct {
    id: u64,
    key: packet.FlowKey,
    last_seen_ns: u64,
};

const FlowContext = struct {
    pub fn hash(_: @This(), key: packet.FlowKey) u64 {
        return key.hash();
    }

    pub fn eql(_: @This(), a: packet.FlowKey, b: packet.FlowKey) bool {
        return a.eql(b);
    }
};

const FlowMap = std.HashMap(packet.FlowKey, Flow, FlowContext, std.hash_map.default_max_load_percentage);

const Touch = struct {
    flow: *Flow,
    created: bool,
};

/// Single-owner bounded UDP association registry. The TUN reader calls
/// `handlePacket` with a monotonic timestamp. It may schedule calls for
/// different flows concurrently, but calls for one flow must be serialized as
/// required by `datagram.Dispatcher`. Expiration and deinit notify the outbound
/// so it can deterministically close retained sockets or proxy streams.
pub const Handler = struct {
    allocator: std.mem.Allocator,
    dispatcher: datagram.Dispatcher,
    options: Options,
    flows: FlowMap,
    next_flow_id: u64 = 1,
    next_identification: u16 = 1,

    pub fn init(
        allocator: std.mem.Allocator,
        dispatcher: datagram.Dispatcher,
        options: Options,
    ) !Handler {
        if (options.max_flows == 0 or options.idle_timeout_ns == 0) return error.InvalidOptions;
        return .{
            .allocator = allocator,
            .dispatcher = dispatcher,
            .options = options,
            .flows = FlowMap.init(allocator),
        };
    }

    pub fn deinit(self: *Handler, io: Io) void {
        while (self.removeAny()) |flow| {
            self.dispatcher.close(flow.id, .shutdown, io);
        }
        self.flows.deinit();
        self.* = undefined;
    }

    /// Parses one IP packet, updates its UDP association, sends its payload to
    /// the selected datagram outbound, and converts each synchronous response
    /// into an IP packet for `packet_sink`.
    pub fn handlePacket(
        self: *Handler,
        bytes: []const u8,
        inbound_tag: ?[]const u8,
        outbound_tag: ?[]const u8,
        now_ns: u64,
        packet_sink: PacketSink,
        io: Io,
    ) !void {
        self.expire(now_ns, io);
        const incoming = try packet.parse(bytes);
        const touched = try self.touch(incoming.key, now_ns);
        const target = targetForKey(incoming.key);
        var response_context: ResponseContext = .{
            .request_key = incoming.key,
            .packet_sink = packet_sink,
            .identification = &self.next_identification,
        };
        const response_sink: datagram.ResponseSink = .{
            .context = &response_context,
            .send_fn = ResponseContext.send,
        };

        self.dispatcher.dispatch(.{
            .flow_id = touched.flow.id,
            .target = target,
            .inbound_tag = inbound_tag,
            .outbound_tag = outbound_tag,
        }, incoming.payload, response_sink, io) catch |err| {
            const failed = self.flows.fetchRemove(incoming.key);
            if (failed) |entry| self.dispatcher.close(entry.value.id, .dispatch_failed, io);
            return err;
        };
    }

    pub fn expire(self: *Handler, now_ns: u64, io: Io) void {
        while (self.removeOneExpired(now_ns)) |flow| {
            self.dispatcher.close(flow.id, .idle_timeout, io);
        }
    }

    pub fn count(self: *const Handler) usize {
        return self.flows.count();
    }

    fn touch(self: *Handler, key: packet.FlowKey, now_ns: u64) !Touch {
        if (self.flows.getPtr(key)) |flow| {
            flow.last_seen_ns = now_ns;
            return .{ .flow = flow, .created = false };
        }
        if (self.flows.count() >= self.options.max_flows) return error.TooManyUdpFlows;

        const id = self.next_flow_id;
        self.next_flow_id +%= 1;
        if (self.next_flow_id == 0) self.next_flow_id = 1;
        try self.flows.put(key, .{ .id = id, .key = key, .last_seen_ns = now_ns });
        return .{ .flow = self.flows.getPtr(key).?, .created = true };
    }

    fn removeOneExpired(self: *Handler, now_ns: u64) ?Flow {
        var iterator = self.flows.iterator();
        while (iterator.next()) |entry| {
            const flow = entry.value_ptr.*;
            const elapsed = if (now_ns >= flow.last_seen_ns) now_ns - flow.last_seen_ns else 0;
            if (elapsed < self.options.idle_timeout_ns) continue;
            return self.flows.fetchRemove(flow.key).?.value;
        }
        return null;
    }

    fn removeAny(self: *Handler) ?Flow {
        var iterator = self.flows.iterator();
        const entry = iterator.next() orelse return null;
        return self.flows.fetchRemove(entry.key_ptr.*).?.value;
    }
};

const ResponseContext = struct {
    request_key: packet.FlowKey,
    packet_sink: PacketSink,
    identification: *u16,

    fn send(
        context: *anyopaque,
        source: net.IpAddress,
        payload: []const u8,
        io: Io,
    ) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        var response_key = self.request_key.reverse();
        switch (source) {
            .ip4 => |address| {
                if (response_key.version != .ip4) return error.ResponseAddressFamilyMismatch;
                @memset(&response_key.source, 0);
                @memcpy(response_key.source[0..4], &address.bytes);
                response_key.source_port = address.port;
            },
            .ip6 => |address| {
                if (response_key.version != .ip6) return error.ResponseAddressFamilyMismatch;
                response_key.source = address.bytes;
                response_key.source_port = address.port;
            },
        }

        var output: [packet.max_mtu]u8 = undefined;
        const identification = self.identification.*;
        self.identification.* +%= 1;
        const bytes = try packet.build(&output, response_key, payload, identification);
        try self.packet_sink.write(bytes, io);
    }
};

fn targetForKey(key: packet.FlowKey) net.IpAddress {
    return switch (key.version) {
        .ip4 => .{ .ip4 = .{
            .bytes = key.destination[0..4].*,
            .port = key.destination_port,
        } },
        .ip6 => .{ .ip6 = .{
            .bytes = key.destination,
            .port = key.destination_port,
            .flow = 0,
            .interface = .none,
        } },
    };
}

const TestHarness = struct {
    dispatches: usize = 0,
    closes: usize = 0,
    last_flow_id: u64 = 0,
    last_close_reason: ?datagram.CloseReason = null,
    reply: bool = true,
    packet_bytes: [packet.max_mtu]u8 = undefined,
    packet_len: usize = 0,

    fn dispatcher(self: *@This()) datagram.Dispatcher {
        return .{ .context = self, .dispatch_fn = dispatch, .close_fn = close };
    }

    fn packetSink(self: *@This()) PacketSink {
        return .{ .context = self, .write_fn = writePacket };
    }

    fn dispatch(
        context: *anyopaque,
        sess: datagram.Session,
        payload: []const u8,
        response_sink: datagram.ResponseSink,
        io: Io,
    ) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.dispatches += 1;
        self.last_flow_id = sess.flow_id;
        if (self.reply) try response_sink.send(sess.target, payload, io);
    }

    fn close(context: *anyopaque, _: u64, reason: datagram.CloseReason, _: Io) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.closes += 1;
        self.last_close_reason = reason;
    }

    fn writePacket(context: *anyopaque, bytes: []const u8, _: Io) !void {
        const self: *@This() = @ptrCast(@alignCast(context));
        @memcpy(self.packet_bytes[0..bytes.len], bytes);
        self.packet_len = bytes.len;
    }
};

fn testKey(last_octet: u8) packet.FlowKey {
    return .{
        .version = .ip4,
        .source = .{ 192, 0, 2, last_octet } ++ ([_]u8{0} ** 12),
        .destination = .{ 198, 51, 100, 53 } ++ ([_]u8{0} ** 12),
        .source_port = 40000 + @as(u16, last_octet),
        .destination_port = 53,
    };
}

test "handler dispatches a UDP packet and emits a checksummed reply" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var harness: TestHarness = .{};
    var handler = try Handler.init(std.testing.allocator, harness.dispatcher(), .{});
    defer handler.deinit(io);

    const key = testKey(10);
    var request: [packet.max_mtu]u8 = undefined;
    const bytes = try packet.build(&request, key, "question", 1);
    try handler.handlePacket(bytes, "tun-in", null, 100, harness.packetSink(), io);

    try std.testing.expectEqual(@as(usize, 1), handler.count());
    try std.testing.expectEqual(@as(usize, 1), harness.dispatches);
    const reply = try packet.parse(harness.packet_bytes[0..harness.packet_len]);
    try std.testing.expect(key.reverse().eql(reply.key));
    try std.testing.expectEqualStrings("question", reply.payload);
}

test "flow capacity is bounded and existing flows remain usable" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var harness: TestHarness = .{ .reply = false };
    var handler = try Handler.init(std.testing.allocator, harness.dispatcher(), .{
        .max_flows = 1,
        .idle_timeout_ns = 100,
    });
    defer handler.deinit(io);

    var buffer: [packet.max_mtu]u8 = undefined;
    const first = try packet.build(&buffer, testKey(1), "a", 1);
    try handler.handlePacket(first, null, null, 0, harness.packetSink(), io);
    const first_flow_id = harness.last_flow_id;

    const second = try packet.build(&buffer, testKey(2), "b", 2);
    try std.testing.expectError(
        error.TooManyUdpFlows,
        handler.handlePacket(second, null, null, 1, harness.packetSink(), io),
    );

    const again = try packet.build(&buffer, testKey(1), "c", 3);
    try handler.handlePacket(again, null, null, 2, harness.packetSink(), io);
    try std.testing.expectEqual(first_flow_id, harness.last_flow_id);
}

test "idle timeout deterministically closes and replaces a flow" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var harness: TestHarness = .{ .reply = false };
    var handler = try Handler.init(std.testing.allocator, harness.dispatcher(), .{
        .max_flows = 1,
        .idle_timeout_ns = 10,
    });
    defer handler.deinit(io);

    var buffer: [packet.max_mtu]u8 = undefined;
    const first = try packet.build(&buffer, testKey(1), "a", 1);
    try handler.handlePacket(first, null, null, 5, harness.packetSink(), io);
    const first_flow_id = harness.last_flow_id;

    handler.expire(14, io);
    try std.testing.expectEqual(@as(usize, 1), handler.count());
    handler.expire(15, io);
    try std.testing.expectEqual(@as(usize, 0), handler.count());
    try std.testing.expectEqual(@as(usize, 1), harness.closes);
    try std.testing.expectEqual(datagram.CloseReason.idle_timeout, harness.last_close_reason.?);

    const second = try packet.build(&buffer, testKey(2), "b", 2);
    try handler.handlePacket(second, null, null, 16, harness.packetSink(), io);
    try std.testing.expect(harness.last_flow_id != first_flow_id);
}
