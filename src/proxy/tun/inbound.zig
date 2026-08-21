const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;
const posix = std.posix;

const config = @import("../../config/mod.zig");
const diagnostics = @import("../../diagnostics.zig");
const log = @import("../../log.zig");
const monitoring = @import("../../monitoring.zig");
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
const reactor_buffer_size = (segment_queue_len + 1) * packet.max_tcp_payload;
const maximum_reactor_connections = 4096;
const maximum_ring_entries: usize = 32768;

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
    pending_segment: ?OwnedSegment = null,
    state_mutex: Io.Mutex = .init,
    ack_condition: Io.Condition = .init,
    state: tcp.State,
    ref_count: std.atomic.Value(usize) = .init(1),
    bridge: ?net.Stream = null,
    reactor_next: ?*Flow = null,
    uplink: ReactorBuffer = .{},
    downlink: ReactorBuffer = .{},
    client_eof: bool = false,
    bridge_eof: bool = false,
    bridge_send_shutdown: bool = false,
    fin_queued: bool = false,
    reactor_failed: bool = false,
    recv_pending: bool = false,
    send_pending: bool = false,
    cancellation_requested: bool = false,

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

const ReactorBuffer = struct {
    bytes: [reactor_buffer_size]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn empty(self: *const ReactorBuffer) bool {
        return self.start == self.end;
    }

    fn readable(self: *ReactorBuffer) []u8 {
        return self.bytes[self.start..self.end];
    }

    fn writable(self: *ReactorBuffer) []u8 {
        if (self.end == self.bytes.len and self.start != 0) self.compact();
        return self.bytes[self.end..];
    }

    fn append(self: *ReactorBuffer, bytes: []const u8) bool {
        const destination = self.writable();
        if (destination.len < bytes.len) return false;
        @memcpy(destination[0..bytes.len], bytes);
        self.end += bytes.len;
        return true;
    }

    fn consume(self: *ReactorBuffer, count: usize) void {
        std.debug.assert(count <= self.end - self.start);
        self.start += count;
        if (self.empty()) {
            self.start = 0;
            self.end = 0;
        }
    }

    fn compact(self: *ReactorBuffer) void {
        if (self.start == 0) return;
        const len = self.end - self.start;
        std.mem.copyForwards(u8, self.bytes[0..len], self.bytes[self.start..self.end]);
        self.start = 0;
        self.end = len;
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

const TunReactor = struct {
    manager: *FlowManager,
    allocator: std.mem.Allocator,
    ring: linux.IoUring,
    ring_live: bool = true,
    wake_fd: posix.fd_t,
    completions: []linux.io_uring_cqe,
    pending_head: std.atomic.Value(?*Flow) = .init(null),
    admission_mutex: std.atomic.Mutex = .unlocked,
    stopped: std.atomic.Value(bool) = .init(false),
    active_head: ?*Flow = null,
    active_count: usize = 0,
    wake_value: u64 = 0,
    wake_pending: bool = false,
    timer_spec: linux.kernel_timespec = .{
        .sec = 0,
        .nsec = retransmission_poll_ms * std.time.ns_per_ms,
    },
    timer_pending: bool = false,

    const wake_user_data: u64 = 1;
    const timer_user_data: u64 = 2;
    const cancel_user_data: u64 = 3;
    const recv_tag: usize = 1;
    const send_tag: usize = 2;
    const tag_mask: usize = 3;

    fn init(manager: *FlowManager, allocator: std.mem.Allocator, max_connections: usize) !TunReactor {
        if (max_connections == 0 or max_connections > maximum_reactor_connections)
            return error.InvalidTunReactorCapacity;
        const required_entries = max_connections * 4 + 8;
        const entries = try tunRingEntries(required_entries);
        const completions = try allocator.alloc(linux.io_uring_cqe, required_entries);
        errdefer allocator.free(completions);
        const wake_rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
        if (linux.errno(wake_rc) != .SUCCESS) return error.SystemResources;
        errdefer _ = linux.close(@intCast(wake_rc));
        const ring = linux.IoUring.init(entries, 0) catch |err| {
            return err;
        };
        return .{
            .manager = manager,
            .allocator = allocator,
            .ring = ring,
            .wake_fd = @intCast(wake_rc),
            .completions = completions,
        };
    }

    fn deinit(self: *TunReactor) void {
        self.stop();
        if (self.ring_live) self.ring.deinit();
        _ = linux.close(self.wake_fd);
        self.allocator.free(self.completions);
    }

    fn stop(self: *TunReactor) void {
        lockAdmission(&self.admission_mutex);
        const was_stopped = self.stopped.swap(true, .release);
        self.admission_mutex.unlock();
        if (was_stopped) return;
        self.wake();
    }

    fn adopt(self: *TunReactor, flow: *Flow, bridge: net.Stream) !void {
        lockAdmission(&self.admission_mutex);
        defer self.admission_mutex.unlock();
        if (self.stopped.load(.acquire)) return error.ReactorStopped;
        flow.bridge = bridge;
        var head = self.pending_head.load(.monotonic);
        while (true) {
            flow.reactor_next = head;
            head = self.pending_head.cmpxchgWeak(head, flow, .release, .monotonic) orelse break;
        }
        self.wake();
    }

    fn notify(self: *TunReactor) void {
        self.wake();
    }

    fn wake(self: *TunReactor) void {
        var value: u64 = 1;
        while (true) switch (linux.errno(linux.write(self.wake_fd, @ptrCast(&value), @sizeOf(u64)))) {
            .SUCCESS, .AGAIN => return,
            .INTR => continue,
            else => return,
        };
    }

    fn run(self: *TunReactor, io: Io) !void {
        defer {
            self.stop();
            self.ring.deinit();
            self.ring_live = false;
            self.closeAll(io);
        }
        while (!self.stopped.load(.acquire)) {
            try io.checkCancel();
            self.takePending();
            self.serviceAll(io);
            try self.armOperations();
            _ = self.ring.submit_and_wait(1) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => return err,
            };
            const count = try self.ring.copy_cqes(self.completions, 0);
            for (self.completions[0..count]) |completion| self.complete(completion);
        }
    }

    fn takePending(self: *TunReactor) void {
        var pending = self.pending_head.swap(null, .acquire);
        while (pending) |flow| {
            const next = flow.reactor_next;
            flow.reactor_next = self.active_head;
            self.active_head = flow;
            self.active_count += 1;
            pending = next;
        }
    }

    fn serviceAll(self: *TunReactor, io: Io) void {
        const now_ms = nowMilliseconds(io);
        var link = &self.active_head;
        while (link.*) |flow| {
            self.serviceFlow(flow, now_ms, io);
            if (flowReadyToRelease(flow)) {
                link.* = flow.reactor_next;
                flow.bridge.?.close(io);
                flow.bridge = null;
                self.manager.removeAndRelease(flow, io);
                self.active_count -= 1;
            } else {
                link = &flow.reactor_next;
            }
        }
    }

    fn serviceFlow(self: *TunReactor, flow: *Flow, now_ms: u64, io: Io) void {
        if (flow.reactor_failed) {
            self.cancelFlow(flow);
            return;
        }

        if (!flow.send_pending and flow.uplink.end == flow.uplink.bytes.len) flow.uplink.compact();
        while (true) {
            var segment = if (flow.pending_segment) |pending| pending else getQueuedSegment(flow, io) orelse break;
            flow.pending_segment = null;
            if (segment.payload_len > flow.uplink.bytes.len - flow.uplink.end) {
                flow.pending_segment = segment;
                break;
            }
            const result = flow.processSegment(&segment, io) catch {
                flow.reactor_failed = true;
                break;
            };
            if (result.reset or flow.state.phase == .terminal) {
                flow.reactor_failed = true;
                break;
            }
            if (segment.flags.syn) {
                flow.resendSynAck(io) catch {
                    flow.reactor_failed = true;
                    break;
                };
                continue;
            }
            if (result.payload_len != 0) {
                const start: usize = result.payload_skip;
                const len: usize = result.payload_len;
                if (!flow.uplink.append(segment.bytes()[start..][0..len])) {
                    flow.reactor_failed = true;
                    break;
                }
            }
            if (result.accepted_fin) flow.client_eof = true;
        }

        while (!flow.downlink.empty()) {
            const segment = flow.state.queueData(flow.downlink.readable(), now_ms) orelse break;
            flow.sendTx(segment, io) catch {
                flow.reactor_failed = true;
                break;
            };
            flow.downlink.consume(segment.payload_len);
        }

        if (flow.bridge_eof and flow.downlink.empty() and !flow.fin_queued) {
            if (flow.state.queueFin(now_ms)) |segment| {
                flow.fin_queued = true;
                flow.sendTx(segment, io) catch {
                    flow.reactor_failed = true;
                };
            }
        }
        if (flow.client_eof and flow.uplink.empty() and !flow.bridge_send_shutdown) {
            _ = linux.shutdown(flow.bridge.?.socket.handle, linux.SHUT.WR);
            flow.bridge_send_shutdown = true;
        }

        _ = flow.state.expired(now_ms);
        if (flow.state.retransmitDue(now_ms)) |segment| {
            flow.sendTx(segment, io) catch {
                flow.reactor_failed = true;
            };
        }
        if (flow.state.phase == .terminal) flow.reactor_failed = true;
        if (flow.reactor_failed) self.cancelFlow(flow);
    }

    fn armOperations(self: *TunReactor) !void {
        if (!self.wake_pending) {
            _ = try self.ring.read(wake_user_data, self.wake_fd, .{ .buffer = std.mem.asBytes(&self.wake_value) }, 0);
            self.wake_pending = true;
        }
        if (!self.timer_pending) {
            _ = try self.ring.timeout(timer_user_data, &self.timer_spec, 0, 0);
            self.timer_pending = true;
        }
        var current = self.active_head;
        while (current) |flow| : (current = flow.reactor_next) {
            if (flow.reactor_failed) continue;
            if (!flow.recv_pending and !flow.bridge_eof and flow.downlink.empty()) {
                const writable = flow.downlink.writable();
                _ = try self.ring.recv(flowUserData(flow, recv_tag), flow.bridge.?.socket.handle, .{ .buffer = writable }, 0);
                flow.recv_pending = true;
            }
            if (!flow.send_pending and !flow.uplink.empty()) {
                _ = try self.ring.send(flowUserData(flow, send_tag), flow.bridge.?.socket.handle, flow.uplink.readable(), linux.MSG.NOSIGNAL);
                flow.send_pending = true;
            }
        }
        _ = try self.ring.submit();
    }

    fn complete(self: *TunReactor, completion: linux.io_uring_cqe) void {
        if (completion.user_data == wake_user_data) {
            self.wake_pending = false;
            return;
        }
        if (completion.user_data == timer_user_data) {
            self.timer_pending = false;
            return;
        }
        if (completion.user_data == cancel_user_data) return;

        const pointer: usize = @intCast(completion.user_data & ~@as(u64, tag_mask));
        const flow: *Flow = @ptrFromInt(pointer);
        const tag: usize = @intCast(completion.user_data & tag_mask);
        if (tag == recv_tag) {
            flow.recv_pending = false;
            if (completion.res > 0) {
                flow.downlink.end += @intCast(completion.res);
            } else if (completion.res == 0) {
                flow.bridge_eof = true;
            } else if (completionErrno(completion.res) != .CANCELED) {
                flow.reactor_failed = true;
            }
            return;
        }
        std.debug.assert(tag == send_tag);
        flow.send_pending = false;
        if (completion.res > 0) {
            flow.uplink.consume(@intCast(completion.res));
        } else if (completion.res == 0 or completionErrno(completion.res) != .CANCELED) {
            flow.reactor_failed = true;
        }
    }

    fn cancelFlow(self: *TunReactor, flow: *Flow) void {
        if (flow.cancellation_requested) return;
        flow.cancellation_requested = true;
        if (flow.recv_pending) _ = self.ring.cancel(cancel_user_data, flowUserData(flow, recv_tag), 0) catch {};
        if (flow.send_pending) _ = self.ring.cancel(cancel_user_data, flowUserData(flow, send_tag), 0) catch {};
    }

    fn closeAll(self: *TunReactor, io: Io) void {
        var current = self.active_head;
        while (current) |flow| {
            const next = flow.reactor_next;
            flow.bridge.?.close(io);
            self.manager.removeAndRelease(flow, io);
            current = next;
        }
        self.active_head = null;
        var pending = self.pending_head.swap(null, .acquire);
        while (pending) |flow| {
            const next = flow.reactor_next;
            flow.bridge.?.close(io);
            self.manager.removeAndRelease(flow, io);
            pending = next;
        }
    }

    fn flowUserData(flow: *Flow, tag: usize) u64 {
        const pointer = @intFromPtr(flow);
        std.debug.assert(pointer & tag_mask == 0);
        return @intCast(pointer | tag);
    }
};

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
    mutex: Io.Mutex = .init,
    group: Io.Group = .init,
    next_isn: std.atomic.Value(u32) = .init(0x13579bdf),
    reactor: TunReactor,

    fn init(
        allocator: std.mem.Allocator,
        dispatcher: session.Dispatcher,
        device: *Device,
        max_connections: usize,
    ) !FlowManager {
        var flows = FlowMap.init(allocator);
        errdefer flows.deinit();
        var manager: FlowManager = undefined;
        manager = .{
            .allocator = allocator,
            .dispatcher = dispatcher,
            .device = device,
            .max_connections = max_connections,
            .flows = flows,
            .reactor = undefined,
        };
        manager.reactor = try TunReactor.init(&manager, allocator, max_connections);
        return manager;
    }

    fn start(self: *FlowManager, io: Io) !void {
        // init returns the manager by value, so repair the reactor's self pointer
        // after it reaches its stable caller-owned address.
        self.reactor.manager = self;
        try self.group.concurrent(io, runTunReactor, .{ &self.reactor, io });
    }

    fn deinit(self: *FlowManager, io: Io) void {
        self.reactor.stop();
        self.group.cancel(io);
        std.debug.assert(self.flows.count() == 0);
        self.reactor.deinit();
        self.flows.deinit();
    }

    fn handle(self: *FlowManager, segment: packet.Segment, inbound_tag: ?[]const u8, io: Io) !void {
        try self.mutex.lock(io);
        if (self.flows.get(segment.key)) |flow| {
            defer self.mutex.unlock(io);
            const owned = OwnedSegment.init(segment) orelse return;
            const queued = flow.queue.put(io, &.{owned}, 0) catch return;
            if (queued != 0) self.reactor.notify();
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
    monitoring.registry.listenerStarted();
    defer monitoring.registry.listenerStopped();

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

fn getQueuedSegment(flow: *Flow, io: Io) ?OwnedSegment {
    var queued: [1]OwnedSegment = undefined;
    const count = flow.queue.get(io, &queued, 0) catch 0;
    return if (count == 0) null else queued[0];
}

fn attach(file: Io.File, requested_name: []const u8) !void {
    var request: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(request.ifrn.name[0..requested_name.len], requested_name);
    request.ifru.flags = @bitCast(iff_tun | iff_no_pi);
    const rc = linux.ioctl(file.handle, tun_set_iff, @intFromPtr(&request));
    if (linux.errno(rc) != .SUCCESS) return error.TunAttachFailed;
}

fn runFlow(flow: *Flow, io: Io) Io.Cancelable!void {
    var adopted = false;
    defer if (!adopted) flow.manager.removeAndRelease(flow, io);
    diagnostics.setThreadName("xz-tun-flow");

    var preface_buffer: [session.max_preface_len]u8 = undefined;
    const preface_len = waitForPreface(flow, &preface_buffer, io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
    const preface = preface_buffer[0..preface_len];

    const pair = createLocalPair() catch return;
    const context = flow.manager.allocator.create(DispatchContext) catch {
        pair[0].close(io);
        pair[1].close(io);
        return;
    };
    context.* = .{
        .allocator = flow.manager.allocator,
        .dispatcher = flow.manager.dispatcher,
        .stream = pair[0],
        .key = flow.key,
        .inbound_tag = flow.inbound_tag,
        .preface_len = preface.len,
    };
    @memcpy(context.preface[0..preface.len], preface);
    flow.manager.group.concurrent(io, dispatchFlow, .{ context, io }) catch {
        flow.manager.allocator.destroy(context);
        pair[0].close(io);
        pair[1].close(io);
        return;
    };
    flow.manager.reactor.adopt(flow, pair[1]) catch {
        pair[1].close(io);
        return;
    };
    adopted = true;
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

const DispatchContext = struct {
    allocator: std.mem.Allocator,
    dispatcher: session.Dispatcher,
    stream: net.Stream,
    key: packet.FlowKey,
    inbound_tag: ?[]const u8,
    preface_len: usize,
    preface: [session.max_preface_len]u8 = undefined,
};

fn dispatchFlow(context: *DispatchContext, io: Io) Io.Cancelable!void {
    defer context.allocator.destroy(context);
    defer context.stream.close(io);
    const target = targetForKey(context.key);
    context.dispatcher.dispatch(context.stream, .{
        .target = .{ .address = target },
        .inbound_tag = context.inbound_tag,
        .sniffed_domain = sniff.domain(context.preface[0..context.preface_len]),
        .preferred_family = std.meta.activeTag(target),
    }, .{ .bytes = context.preface[0..context.preface_len] }, io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn runTunReactor(reactor: *TunReactor, io: Io) Io.Cancelable!void {
    diagnostics.setThreadName("xz-tun-uring");
    reactor.run(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => log.err("tun io_uring reactor stopped: {s}\n", .{@errorName(err)}),
    };
}

fn completionErrno(result: i32) linux.E {
    std.debug.assert(result < 0);
    return @enumFromInt(@as(u16, @intCast(-result)));
}

fn lockAdmission(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

fn flowReadyToRelease(flow: *const Flow) bool {
    return flow.reactor_failed and !flow.recv_pending and !flow.send_pending;
}

fn tunRingEntries(required: usize) !u16 {
    if (required > maximum_ring_entries) return error.InvalidTunReactorCapacity;
    var entries: u16 = 8;
    while (entries < required) entries *= 2;
    return entries;
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

test "reactor buffers preserve order across partial writes and compaction" {
    var buffer: ReactorBuffer = .{};
    try std.testing.expect(buffer.append("first"));
    buffer.consume(3);
    try std.testing.expectEqualStrings("st", buffer.readable());
    buffer.end = buffer.bytes.len;
    buffer.start = buffer.bytes.len - 2;
    @memcpy(buffer.bytes[buffer.start..buffer.end], "xy");
    try std.testing.expect(buffer.append("next"));
    try std.testing.expectEqualStrings("xynext", buffer.readable());
}

test "TUN io_uring completions preserve partial bridge IO" {
    var manager: FlowManager = undefined;
    var reactor: TunReactor = .{
        .manager = &manager,
        .allocator = std.testing.allocator,
        .ring = undefined,
        .wake_fd = -1,
        .completions = undefined,
    };
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
        .state = tcp.State.init(1, 2, 65535, 1460, 0),
        .recv_pending = true,
    };
    flow.initializeQueue();
    @memcpy(flow.downlink.bytes[0..5], "reply");

    reactor.complete(.{
        .user_data = TunReactor.flowUserData(&flow, TunReactor.recv_tag),
        .res = 5,
        .flags = 0,
    });
    try std.testing.expectEqualStrings("reply", flow.downlink.readable());
    try std.testing.expect(!flow.recv_pending);

    try std.testing.expect(flow.uplink.append("request"));
    flow.send_pending = true;
    reactor.complete(.{
        .user_data = TunReactor.flowUserData(&flow, TunReactor.send_tag),
        .res = 3,
        .flags = 0,
    });
    try std.testing.expectEqualStrings("uest", flow.uplink.readable());
    try std.testing.expect(!flow.send_pending);
}

test "TUN canceled CQE gates flow release" {
    var manager: FlowManager = undefined;
    var reactor: TunReactor = .{
        .manager = &manager,
        .allocator = std.testing.allocator,
        .ring = undefined,
        .wake_fd = -1,
        .completions = undefined,
    };
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
        .state = tcp.State.init(1, 2, 65535, 1460, 0),
        .reactor_failed = true,
        .recv_pending = true,
        .cancellation_requested = true,
    };
    flow.initializeQueue();

    try std.testing.expect(!flowReadyToRelease(&flow));
    reactor.complete(.{
        .user_data = TunReactor.cancel_user_data,
        .res = 0,
        .flags = 0,
    });
    try std.testing.expect(!flowReadyToRelease(&flow));
    reactor.complete(.{
        .user_data = TunReactor.flowUserData(&flow, TunReactor.recv_tag),
        .res = -@as(i32, @intFromEnum(linux.E.CANCELED)),
        .flags = 0,
    });
    try std.testing.expect(flowReadyToRelease(&flow));
}

test "TUN io_uring capacity fits the u16 ring API" {
    try std.testing.expectEqual(
        @as(u16, maximum_ring_entries),
        try tunRingEntries(maximum_reactor_connections * 4 + 8),
    );
    try std.testing.expectError(
        error.InvalidTunReactorCapacity,
        tunRingEntries(maximum_ring_entries + 1),
    );
}

test "TUN io_uring preserves an interactive request response stream" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const packet_pair = try createTestSocketPair(posix.SOCK.SEQPACKET);
    var device_file: Io.File = .{
        .handle = packet_pair[0].socket.handle,
        .flags = .{ .nonblocking = false },
    };
    defer device_file.close(io);
    defer packet_pair[1].close(io);

    var device: Device = .{ .file = device_file, .mtu = packet.max_mtu };
    var manager = try FlowManager.init(std.testing.allocator, undefined, &device, 1);
    defer manager.deinit(io);
    try manager.start(io);

    const key: packet.FlowKey = .{
        .version = .ip4,
        .source = .{ 192, 0, 2, 2 } ++ ([_]u8{0} ** 12),
        .destination = .{ 198, 51, 100, 10 } ++ ([_]u8{0} ** 12),
        .source_port = 40000,
        .destination_port = 443,
    };
    const client_sequence: u32 = 1000;
    const server_sequence: u32 = 2000;
    var state = tcp.State.init(client_sequence, server_sequence, 65535, 1460, nowMilliseconds(io));
    _ = state.queueSynAck(nowMilliseconds(io));
    _ = state.onSegment(client_sequence + 1, server_sequence + 1, .{ .ack = true }, 65535, 0, nowMilliseconds(io));

    const flow = try std.testing.allocator.create(Flow);
    flow.* = .{
        .key = key,
        .inbound_tag = null,
        .manager = &manager,
        .state = state,
    };
    flow.initializeQueue();
    try manager.flows.put(key, flow);

    const bridge_pair = try createLocalPair();
    defer bridge_pair[0].close(io);
    try manager.reactor.adopt(flow, bridge_pair[1]);

    var next_client_sequence = client_sequence + 1;
    var next_server_sequence = server_sequence + 1;
    var packet_buffer: [packet.max_mtu]u8 = undefined;
    var uplink_buffer: [64]u8 = undefined;
    var bridge_write_buffer: [64]u8 = undefined;
    var bridge_writer = bridge_pair[0].writer(io, &bridge_write_buffer);

    for (0..8) |round| {
        var request: [13]u8 = undefined;
        @memset(&request, @intCast(round + 1));
        const queued = try flow.queue.put(io, &.{.{
            .sequence = next_client_sequence,
            .acknowledgment = next_server_sequence,
            .flags = .{ .ack = true, .psh = true },
            .window = 65535,
            .maximum_segment_size = null,
            .payload_len = request.len,
            .payload = request ++ ([_]u8{undefined} ** (packet.max_tcp_payload - request.len)),
        }}, 0);
        try std.testing.expectEqual(@as(usize, 1), queued);
        manager.reactor.notify();

        const uplink = try bridge_pair[0].socket.receiveTimeout(io, &uplink_buffer, .{
            .duration = .{ .raw = Io.Duration.fromSeconds(2), .clock = .awake },
        });
        try std.testing.expectEqualSlices(u8, &request, uplink.data);
        next_client_sequence +%= request.len;

        const request_ack = try packet_pair[1].socket.receiveTimeout(io, &packet_buffer, .{
            .duration = .{ .raw = Io.Duration.fromSeconds(2), .clock = .awake },
        });
        const parsed_ack = try packet.parse(request_ack.data);
        try std.testing.expect(parsed_ack.flags.ack);
        try std.testing.expectEqual(@as(usize, 0), parsed_ack.payload.len);
        try std.testing.expectEqual(next_client_sequence, parsed_ack.acknowledgment);

        if (round == 3) {
            const stale = try flow.queue.put(io, &.{.{
                .sequence = next_client_sequence -% @as(u32, request.len) -% 1,
                .acknowledgment = next_server_sequence,
                .flags = .{ .ack = true },
                .window = 0,
                .maximum_segment_size = null,
                .payload_len = 0,
                .payload = undefined,
            }}, 0);
            try std.testing.expectEqual(@as(usize, 1), stale);
            const barrier = try flow.queue.put(io, &.{.{
                .sequence = client_sequence,
                .acknowledgment = 0,
                .flags = .{ .syn = true },
                .window = 65535,
                .maximum_segment_size = 1460,
                .payload_len = 0,
                .payload = undefined,
            }}, 0);
            try std.testing.expectEqual(@as(usize, 1), barrier);
            manager.reactor.notify();
            const barrier_ack = try packet_pair[1].socket.receiveTimeout(io, &packet_buffer, .{
                .duration = .{ .raw = Io.Duration.fromSeconds(2), .clock = .awake },
            });
            try std.testing.expectEqual(@as(usize, 0), (try packet.parse(barrier_ack.data)).payload.len);
        }

        var response: [17]u8 = undefined;
        @memset(&response, @intCast(0x80 + round));
        try bridge_writer.interface.writeAll(&response);
        try bridge_writer.interface.flush();

        const emitted = try packet_pair[1].socket.receiveTimeout(io, &packet_buffer, .{
            .duration = .{ .raw = Io.Duration.fromSeconds(2), .clock = .awake },
        });
        const parsed = try packet.parse(emitted.data);
        try std.testing.expectEqualSlices(u8, &response, parsed.payload);
        try std.testing.expectEqual(next_server_sequence, parsed.sequence);
        next_server_sequence +%= response.len;

        const acked = try flow.queue.put(io, &.{.{
            .sequence = next_client_sequence,
            .acknowledgment = next_server_sequence,
            .flags = .{ .ack = true },
            .window = 65535,
            .maximum_segment_size = null,
            .payload_len = 0,
            .payload = undefined,
        }}, 0);
        try std.testing.expectEqual(@as(usize, 1), acked);
        manager.reactor.notify();
    }
}

fn createTestSocketPair(socket_type: u32) ![2]net.Stream {
    var fds: [2]posix.socket_t = undefined;
    while (true) switch (posix.errno(posix.system.socketpair(
        posix.AF.UNIX,
        socket_type | posix.SOCK.CLOEXEC,
        0,
        &fds,
    ))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.SocketPairFailed,
    };
    const address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    return .{
        .{ .socket = .{ .handle = fds[0], .address = address } },
        .{ .socket = .{ .handle = fds[1], .address = address } },
    };
}
