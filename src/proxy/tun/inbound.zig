const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const posix = std.posix;

const config = @import("../../config/mod.zig");
const diagnostics = @import("../../diagnostics.zig");
const log = @import("../../log.zig");
const session = @import("../../net/session.zig");
const sniff = @import("../../net/sniff.zig");
pub const packet = @import("packet.zig");
pub const tcp = @import("tcp.zig");

const linux = std.os.linux;
const tun_set_iff = 0x400454ca;
const iff_tun: u16 = 0x0001;
const iff_no_pi: u16 = 0x1000;
const advertised_window: u16 = 65535;
const segment_queue_len = 16;
const retransmission_poll_ms = 50;

pub const Error = error{
    TunRequiresLinux,
    MissingTunSettings,
    TunAttachFailed,
    TooManyConnections,
};

const OwnedSegment = struct {
    sequence: u32,
    acknowledgment: u32,
    flags: packet.Flags,
    window: u16,
    maximum_segment_size: ?u16,
    payload_len: u16,
    payload: [packet.max_tcp_payload]u8,

    fn init(segment: packet.Segment) ?OwnedSegment {
        if (segment.payload.len > packet.max_tcp_payload) return null;
        var owned: OwnedSegment = .{
            .sequence = segment.sequence,
            .acknowledgment = segment.acknowledgment,
            .flags = segment.flags,
            .window = segment.window,
            .maximum_segment_size = segment.maximum_segment_size,
            .payload_len = @intCast(segment.payload.len),
            .payload = undefined,
        };
        @memcpy(owned.payload[0..segment.payload.len], segment.payload);
        return owned;
    }

    fn bytes(self: *const OwnedSegment) []const u8 {
        return self.payload[0..self.payload_len];
    }
};

const Flow = struct {
    key: packet.FlowKey,
    inbound_tag: ?[]const u8,
    manager: *FlowManager,
    queue_storage: [segment_queue_len]OwnedSegment = undefined,
    queue: Io.Queue(OwnedSegment) = undefined,
    state_mutex: Io.Mutex = .init,
    ack_condition: Io.Condition = .init,
    state: tcp.State,
    ref_count: std.atomic.Value(usize) = .init(1),

    fn initializeQueue(self: *Flow) void {
        self.queue = .init(&self.queue_storage);
    }

    fn retain(self: *Flow) void {
        const previous = self.ref_count.fetchAdd(1, .monotonic);
        std.debug.assert(previous != 0);
    }

    fn release(self: *Flow) void {
        const previous = self.ref_count.fetchSub(1, .release);
        std.debug.assert(previous != 0);
        if (previous == 1) {
            _ = self.ref_count.load(.acquire);
            self.manager.allocator.destroy(self);
        }
    }

    fn processSegment(self: *Flow, segment: *const OwnedSegment, io: Io) !tcp.ReceiveResult {
        try self.state_mutex.lock(io);
        const previous_una = self.state.send_una;
        const previous_window = self.state.send_window;
        const result = self.state.onSegment(
            segment.sequence,
            segment.acknowledgment,
            segment.flags,
            segment.window,
            segment.payload_len,
            nowMilliseconds(io),
        );
        const acknowledgment = self.state.recv_next;
        const sequence = self.state.send_next;
        const terminal = self.state.phase == .terminal;
        if (previous_una != self.state.send_una or previous_window != self.state.send_window or result.reset or terminal) {
            self.ack_condition.broadcast(io);
        }
        self.state_mutex.unlock(io);

        if (result.fast_retransmit) |retry| try self.sendTx(retry, io);
        if (result.send_ack) {
            try self.manager.device.writeTcp(self.key, sequence, acknowledgment, .{ .ack = true }, &.{}, io);
        }
        if (terminal) self.queue.close(io);
        return result;
    }

    fn resendSynAck(self: *Flow, io: Io) !void {
        try self.state_mutex.lock(io);
        const syn = if (self.state.tx_count != 0 and self.state.tx[0].flags.syn) self.state.tx[0] else null;
        const sequence = self.state.send_next;
        const acknowledgment = self.state.recv_next;
        self.state_mutex.unlock(io);
        if (syn) |segment| {
            try self.sendTx(segment, io);
        } else {
            try self.manager.device.writeTcp(self.key, sequence, acknowledgment, .{ .ack = true }, &.{}, io);
        }
    }

    fn sendTx(self: *Flow, segment: tcp.TxSegment, io: Io) !void {
        try self.state_mutex.lock(io);
        const acknowledgment = self.state.recv_next;
        self.state_mutex.unlock(io);
        try self.manager.device.writeTcp(
            self.key,
            segment.sequence,
            acknowledgment,
            segment.flags,
            segment.bytes(),
            io,
        );
    }

    fn sendData(self: *Flow, bytes: []const u8, io: Io) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            try self.state_mutex.lock(io);
            var queued: ?tcp.TxSegment = null;
            while (self.state.phase != .terminal) {
                queued = self.state.queueData(bytes[offset..], nowMilliseconds(io));
                if (queued != null) break;
                try self.ack_condition.wait(io, &self.state_mutex);
            }
            if (self.state.phase == .terminal) {
                self.state_mutex.unlock(io);
                return error.ConnectionResetByPeer;
            }
            self.state_mutex.unlock(io);
            try self.sendTx(queued.?, io);
            offset += queued.?.payload_len;
        }
    }

    fn sendFinAndWait(self: *Flow, io: Io) !void {
        try self.state_mutex.lock(io);
        var fin: ?tcp.TxSegment = null;
        while (self.state.phase != .terminal and !self.state.local_fin_sent) {
            fin = self.state.queueFin(nowMilliseconds(io));
            if (fin != null) break;
            try self.ack_condition.wait(io, &self.state_mutex);
        }
        const terminal = self.state.phase == .terminal;
        self.state_mutex.unlock(io);
        if (terminal) return;
        if (fin) |segment| try self.sendTx(segment, io);

        try self.state_mutex.lock(io);
        defer self.state_mutex.unlock(io);
        while (self.state.phase != .terminal) {
            try self.ack_condition.wait(io, &self.state_mutex);
        }
    }
};

const FlowContext = struct {
    pub fn hash(_: FlowContext, key: packet.FlowKey) u64 {
        return key.hash();
    }

    pub fn eql(_: FlowContext, a: packet.FlowKey, b: packet.FlowKey) bool {
        return a.eql(b);
    }
};

const FlowMap = std.HashMap(packet.FlowKey, *Flow, FlowContext, 80);

const Device = struct {
    file: Io.File,
    mtu: u16,
    write_mutex: Io.Mutex = .init,
    next_identification: std.atomic.Value(u32) = .init(1),

    fn writeTcp(
        self: *Device,
        key: packet.FlowKey,
        sequence: u32,
        acknowledgment: u32,
        flags: packet.Flags,
        payload: []const u8,
        io: Io,
    ) !void {
        var buffer: [packet.max_mtu]u8 = undefined;
        const identification: u16 = @truncate(self.next_identification.fetchAdd(1, .monotonic));
        const bytes = try packet.buildForMtu(
            buffer[0..self.mtu],
            key,
            sequence,
            acknowledgment,
            flags,
            advertised_window,
            payload,
            identification,
            self.mtu,
        );
        try self.write_mutex.lock(io);
        defer self.write_mutex.unlock(io);
        try self.file.writeStreamingAll(io, bytes);
    }
};

const FlowManager = struct {
    allocator: std.mem.Allocator,
    dispatcher: session.Dispatcher,
    device: *Device,
    max_connections: usize,
    flows: FlowMap,
    timer_snapshot: []*Flow,
    mutex: Io.Mutex = .init,
    group: Io.Group = .init,
    next_isn: std.atomic.Value(u32) = .init(0x13579bdf),

    fn init(
        allocator: std.mem.Allocator,
        dispatcher: session.Dispatcher,
        device: *Device,
        max_connections: usize,
    ) !FlowManager {
        return .{
            .allocator = allocator,
            .dispatcher = dispatcher,
            .device = device,
            .max_connections = max_connections,
            .flows = FlowMap.init(allocator),
            .timer_snapshot = try allocator.alloc(*Flow, max_connections),
        };
    }

    fn start(self: *FlowManager, io: Io) !void {
        try self.group.concurrent(io, retransmissionPump, .{ self, io });
    }

    fn deinit(self: *FlowManager, io: Io) void {
        self.group.cancel(io);
        std.debug.assert(self.flows.count() == 0);
        self.allocator.free(self.timer_snapshot);
        self.flows.deinit();
    }

    fn handle(self: *FlowManager, segment: packet.Segment, inbound_tag: ?[]const u8, io: Io) !void {
        try self.mutex.lock(io);
        if (self.flows.get(segment.key)) |flow| {
            defer self.mutex.unlock(io);
            const owned = OwnedSegment.init(segment) orelse return;
            _ = flow.queue.put(io, &.{owned}, 0) catch return;
            return;
        }

        if (!segment.flags.syn or segment.flags.ack or segment.flags.rst) {
            self.mutex.unlock(io);
            if (!segment.flags.rst) try self.sendReset(segment, io);
            return;
        }
        if (self.flows.count() >= self.max_connections) {
            self.mutex.unlock(io);
            try self.sendReset(segment, io);
            return error.TooManyConnections;
        }

        const flow = self.allocator.create(Flow) catch |err| {
            self.mutex.unlock(io);
            return err;
        };
        const isn = self.next_isn.fetchAdd(0x9e3779b9, .monotonic);
        const local_mss: u16 = @intCast(packet.tcpPayloadLimitForMtu(segment.key.version, self.device.mtu));
        var tcp_state = tcp.State.init(
            segment.sequence,
            isn,
            segment.window,
            @min(local_mss, segment.maximum_segment_size orelse local_mss),
            nowMilliseconds(io),
        );
        const syn_ack = tcp_state.queueSynAck(nowMilliseconds(io)) orelse unreachable;
        flow.* = .{
            .key = segment.key,
            .inbound_tag = inbound_tag,
            .manager = self,
            .state = tcp_state,
        };
        flow.initializeQueue();
        self.flows.put(segment.key, flow) catch |err| {
            self.allocator.destroy(flow);
            self.mutex.unlock(io);
            return err;
        };
        self.mutex.unlock(io);

        flow.sendTx(syn_ack, io) catch |err| {
            self.removeAndRelease(flow, io);
            return err;
        };
        self.group.concurrent(io, runFlow, .{ flow, io }) catch |err| {
            self.removeAndRelease(flow, io);
            try self.sendReset(segment, io);
            return err;
        };
    }

    fn sendReset(self: *FlowManager, segment: packet.Segment, io: Io) !void {
        if (segment.flags.ack) {
            try self.device.writeTcp(segment.key, segment.acknowledgment, 0, .{ .rst = true }, &.{}, io);
            return;
        }
        const consumed: u32 = @intCast(segment.payload.len + @intFromBool(segment.flags.syn) + @intFromBool(segment.flags.fin));
        try self.device.writeTcp(
            segment.key,
            0,
            segment.sequence +% consumed,
            .{ .rst = true, .ack = true },
            &.{},
            io,
        );
    }

    fn removeAndRelease(self: *FlowManager, flow: *Flow, io: Io) void {
        terminateFlow(flow, io);
        self.mutex.lockUncancelable(io);
        const removed = self.flows.remove(flow.key);
        self.mutex.unlock(io);
        if (removed) flow.release();
    }

    fn snapshotFlows(self: *FlowManager, io: Io) usize {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);

        var count: usize = 0;
        var iterator = self.flows.valueIterator();
        while (iterator.next()) |flow_ptr| {
            const flow = flow_ptr.*;
            flow.retain();
            self.timer_snapshot[count] = flow;
            count += 1;
        }
        return count;
    }
};

pub fn run(
    inbound: config.Inbound,
    dispatcher: session.Dispatcher,
    allocator: std.mem.Allocator,
    io: Io,
    log_writer: *Io.Writer,
    log_mutex: *Io.Mutex,
) !void {
    if (builtin.os.tag != .linux) return error.TunRequiresLinux;
    const settings = inbound.tun orelse return error.MissingTunSettings;
    var tun_file = try Io.Dir.openFileAbsolute(io, "/dev/net/tun", .{ .mode = .read_write });
    defer tun_file.close(io);
    try attach(tun_file, settings.name);

    var device: Device = .{ .file = tun_file, .mtu = settings.mtu };
    var manager = try FlowManager.init(allocator, dispatcher, &device, settings.max_connections);
    defer manager.deinit(io);
    try manager.start(io);

    {
        try log_mutex.lock(io);
        defer log_mutex.unlock(io);
        try log_writer.print(
            "tun inbound {s} attached to {s} mtu={d} max_connections={d}; configure link and routes externally\n",
            .{ inbound.tag orelse "-", settings.name, settings.mtu, settings.max_connections },
        );
        try log_writer.flush();
    }

    var buffer: [packet.max_mtu]u8 = undefined;
    while (true) {
        const size = try tun_file.readStreaming(io, &.{buffer[0..settings.mtu]});
        if (size == 0) return error.EndOfStream;
        const segment = packet.parse(buffer[0..size]) catch |err| switch (err) {
            error.UnsupportedProtocol,
            error.UnsupportedIpv6Extension,
            error.FragmentedPacket,
            => continue,
            else => {
                log.warn("tun inbound dropped malformed packet: {s}\n", .{@errorName(err)});
                continue;
            },
        };
        manager.handle(segment, inbound.tag, io) catch |err| switch (err) {
            error.TooManyConnections => log.warn("tun inbound at connection capacity; reset new flow\n", .{}),
            error.Canceled => return error.Canceled,
            else => log.warn("tun inbound packet handling failed: {s}\n", .{@errorName(err)}),
        };
    }
}

fn attach(file: Io.File, requested_name: []const u8) !void {
    var request: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(request.ifrn.name[0..requested_name.len], requested_name);
    request.ifru.flags = @bitCast(iff_tun | iff_no_pi);
    const rc = linux.ioctl(file.handle, tun_set_iff, @intFromPtr(&request));
    if (linux.errno(rc) != .SUCCESS) return error.TunAttachFailed;
}

fn runFlow(flow: *Flow, io: Io) Io.Cancelable!void {
    defer flow.manager.removeAndRelease(flow, io);
    diagnostics.setThreadName("xz-tun-flow");

    var preface_buffer: [session.max_preface_len]u8 = undefined;
    const preface_len = waitForPreface(flow, &preface_buffer, io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
    const preface = preface_buffer[0..preface_len];

    const pair = createLocalPair() catch return;
    var dispatch_future = io.concurrent(dispatchFlow, .{ pair[0], flow, preface, io }) catch {
        pair[0].close(io);
        pair[1].close(io);
        return;
    };
    defer _ = dispatch_future.cancel(io) catch {};
    defer pair[1].close(io);

    var outbound_future = io.concurrent(outboundPump, .{ flow, pair[1], io }) catch return;
    defer _ = outbound_future.cancel(io) catch {};
    try inboundPump(flow, pair[1], io);
}

fn waitForPreface(flow: *Flow, buffer: *[session.max_preface_len]u8, io: Io) !usize {
    while (true) {
        const segment = try flow.queue.getOne(io);
        const result = try flow.processSegment(&segment, io);
        if (result.reset) return error.ConnectionResetByPeer;
        if (segment.flags.syn) {
            try flow.resendSynAck(io);
            continue;
        }
        if (result.accepted_fin and result.payload_len == 0) return error.EndOfStream;
        if (result.payload_len == 0) continue;
        const start: usize = result.payload_skip;
        const len: usize = result.payload_len;
        @memcpy(buffer[0..len], segment.bytes()[start..][0..len]);
        return len;
    }
}

fn inboundPump(flow: *Flow, bridge: net.Stream, io: Io) Io.Cancelable!void {
    var write_buffer: [packet.max_tcp_payload]u8 = undefined;
    var writer = bridge.writer(io, &write_buffer);
    const output = &writer.interface;
    var send_shutdown = false;
    while (true) {
        const segment = flow.queue.getOne(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => return,
        };
        const result = flow.processSegment(&segment, io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        if (result.reset) return;
        if (segment.flags.syn) {
            flow.resendSynAck(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return,
            };
            continue;
        }
        if (result.payload_len != 0) {
            const start: usize = result.payload_skip;
            const len: usize = result.payload_len;
            output.writeAll(segment.bytes()[start..][0..len]) catch return;
            output.flush() catch return;
        }
        if (result.accepted_fin and !send_shutdown) {
            bridge.shutdown(io, .send) catch {};
            send_shutdown = true;
        }
    }
}

fn outboundPump(flow: *Flow, bridge: net.Stream, io: Io) Io.Cancelable!void {
    var buffer: [packet.max_tcp_payload]u8 = undefined;
    while (true) {
        const message = bridge.socket.receive(io, &buffer) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        if (message.data.len == 0) {
            flow.sendFinAndWait(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return,
            };
            return;
        }
        flow.sendData(message.data, io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
    }
}

fn dispatchFlow(stream: net.Stream, flow: *Flow, preface: []const u8, io: Io) Io.Cancelable!void {
    defer stream.close(io);
    const target = targetForKey(flow.key);
    flow.manager.dispatcher.dispatch(stream, .{
        .target = .{ .address = target },
        .inbound_tag = flow.inbound_tag,
        .sniffed_domain = sniff.domain(preface),
        .preferred_family = std.meta.activeTag(target),
    }, .{ .bytes = preface }, io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn retransmissionPump(manager: *FlowManager, io: Io) Io.Cancelable!void {
    while (true) {
        try io.sleep(Io.Duration.fromMilliseconds(retransmission_poll_ms), .awake);
        const count = manager.snapshotFlows(io);
        for (manager.timer_snapshot[0..count]) |flow| {
            defer flow.release();
            pollRetransmission(flow, io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => terminateFlow(flow, io),
            };
        }
    }
}

fn pollRetransmission(flow: *Flow, io: Io) !void {
    try flow.state_mutex.lock(io);
    const now_ms = nowMilliseconds(io);
    _ = flow.state.expired(now_ms);
    const retry = flow.state.retransmitDue(now_ms);
    const terminal = flow.state.phase == .terminal;
    if (terminal) flow.ack_condition.broadcast(io);
    flow.state_mutex.unlock(io);

    if (terminal) {
        flow.queue.close(io);
        return;
    }
    if (retry) |segment| try flow.sendTx(segment, io);
}

fn terminateFlow(flow: *Flow, io: Io) void {
    flow.state_mutex.lockUncancelable(io);
    flow.state.phase = .terminal;
    flow.ack_condition.broadcast(io);
    flow.state_mutex.unlock(io);
    flow.queue.close(io);
}

fn nowMilliseconds(io: Io) u64 {
    return @intCast(@max(@as(i64, 0), Io.Timestamp.now(io, .awake).toMilliseconds()));
}

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
            .interface = .{ .index = 0 },
        } },
    };
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

test "shared timer expires a flow without a per-flow timer task" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var manager: FlowManager = undefined;
    const now_ms = nowMilliseconds(io);
    var state = tcp.State.init(1, 2, 65535, 1460, now_ms -| tcp.handshake_timeout_ms);
    _ = state.queueSynAck(now_ms -| tcp.handshake_timeout_ms);
    var flow: Flow = .{
        .key = .{
            .version = .ip4,
            .source = [_]u8{0} ** 16,
            .destination = [_]u8{0} ** 16,
            .source_port = 1,
            .destination_port = 2,
        },
        .inbound_tag = null,
        .manager = &manager,
        .state = state,
    };
    flow.initializeQueue();

    try pollRetransmission(&flow, io);
    try std.testing.expectEqual(tcp.Phase.terminal, flow.state.phase);
    try std.testing.expectError(error.Closed, flow.queue.getOne(io));
}

test "timer snapshot retains flows until polling finishes" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var device: Device = undefined;
    var manager = try FlowManager.init(std.testing.allocator, undefined, &device, 1);
    defer manager.deinit(io);
    const flow = try std.testing.allocator.create(Flow);
    flow.* = .{
        .key = .{
            .version = .ip4,
            .source = [_]u8{0} ** 16,
            .destination = [_]u8{0} ** 16,
            .source_port = 1,
            .destination_port = 2,
        },
        .inbound_tag = null,
        .manager = &manager,
        .state = tcp.State.init(1, 2, 65535, 1460, nowMilliseconds(io)),
    };
    flow.initializeQueue();
    try manager.flows.put(flow.key, flow);

    try std.testing.expectEqual(@as(usize, 1), manager.snapshotFlows(io));
    try std.testing.expectEqual(@as(usize, 2), flow.ref_count.load(.acquire));
    manager.timer_snapshot[0].release();
    try std.testing.expectEqual(@as(usize, 1), flow.ref_count.load(.acquire));
    manager.removeAndRelease(flow, io);
}
