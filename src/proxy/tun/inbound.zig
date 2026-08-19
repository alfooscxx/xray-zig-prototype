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

const linux = std.os.linux;
const tun_set_iff = 0x400454ca;
const iff_tun: u16 = 0x0001;
const iff_no_pi: u16 = 0x1000;
const advertised_window: u16 = 65535;
const segment_queue_len = 16;

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
    payload_len: u16,
    payload: [packet.max_tcp_payload]u8,

    fn init(segment: packet.Segment) ?OwnedSegment {
        if (segment.payload.len > packet.max_tcp_payload) return null;
        var owned: OwnedSegment = .{
            .sequence = segment.sequence,
            .acknowledgment = segment.acknowledgment,
            .flags = segment.flags,
            .window = segment.window,
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
    client_next: u32,
    server_next: u32,
    server_acked: u32,
    client_window: u32,
    client_fin: bool = false,
    reset: bool = false,

    fn initializeQueue(self: *Flow) void {
        self.queue = .init(&self.queue_storage);
    }

    fn observeAck(self: *Flow, segment: *const OwnedSegment, io: Io) !void {
        try self.state_mutex.lock(io);
        defer self.state_mutex.unlock(io);
        self.client_window = segment.window;
        if (segment.flags.ack and sequenceAfter(segment.acknowledgment, self.server_acked) and
            !sequenceAfter(segment.acknowledgment, self.server_next))
        {
            self.server_acked = segment.acknowledgment;
            self.ack_condition.broadcast(io);
        }
        if (segment.flags.rst) {
            self.reset = true;
            self.ack_condition.broadcast(io);
        }
    }

    fn acceptClientData(self: *Flow, segment: *const OwnedSegment, io: Io) !bool {
        try self.state_mutex.lock(io);
        defer self.state_mutex.unlock(io);
        if (segment.sequence != self.client_next) return false;
        self.client_next +%= segment.payload_len;
        if (segment.flags.fin) {
            self.client_next +%= 1;
            self.client_fin = true;
        }
        return true;
    }

    fn sendAck(self: *Flow, io: Io) !void {
        try self.state_mutex.lock(io);
        const sequence = self.server_next;
        const acknowledgment = self.client_next;
        self.state_mutex.unlock(io);
        try self.manager.device.writeTcp(self.key, sequence, acknowledgment, .{ .ack = true }, &.{}, io);
    }

    fn sendSynAck(self: *Flow, io: Io) !void {
        try self.state_mutex.lock(io);
        const sequence = self.server_next -% 1;
        const acknowledgment = self.client_next;
        self.state_mutex.unlock(io);
        try self.manager.device.writeTcp(self.key, sequence, acknowledgment, .{ .syn = true, .ack = true }, &.{}, io);
    }

    fn sendData(self: *Flow, bytes: []const u8, io: Io) !void {
        var offset: usize = 0;
        while (offset < bytes.len) {
            try self.state_mutex.lock(io);
            while (!self.reset and self.client_window <= self.server_next -% self.server_acked) {
                try self.ack_condition.wait(io, &self.state_mutex);
            }
            if (self.reset) {
                self.state_mutex.unlock(io);
                return error.ConnectionResetByPeer;
            }
            const outstanding = self.server_next -% self.server_acked;
            const available: usize = @intCast(self.client_window - outstanding);
            const len = @min(bytes.len - offset, available, packet.tcpPayloadLimit(self.key.version));
            const sequence = self.server_next;
            const acknowledgment = self.client_next;
            self.server_next +%= @intCast(len);
            self.state_mutex.unlock(io);

            try self.manager.device.writeTcp(
                self.key,
                sequence,
                acknowledgment,
                .{ .ack = true, .psh = true },
                bytes[offset..][0..len],
                io,
            );
            offset += len;
        }
    }

    fn sendFinAndWait(self: *Flow, io: Io) !void {
        try self.state_mutex.lock(io);
        if (self.reset) {
            self.state_mutex.unlock(io);
            return;
        }
        const sequence = self.server_next;
        const acknowledgment = self.client_next;
        self.server_next +%= 1;
        const expected_ack = self.server_next;
        self.state_mutex.unlock(io);
        try self.manager.device.writeTcp(self.key, sequence, acknowledgment, .{ .fin = true, .ack = true }, &.{}, io);

        try self.state_mutex.lock(io);
        defer self.state_mutex.unlock(io);
        while (!self.reset and self.server_acked != expected_ack) {
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
        const bytes = try packet.build(
            buffer[0..self.mtu],
            key,
            sequence,
            acknowledgment,
            flags,
            advertised_window,
            payload,
            identification,
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

    fn init(
        allocator: std.mem.Allocator,
        dispatcher: session.Dispatcher,
        device: *Device,
        max_connections: usize,
    ) FlowManager {
        return .{
            .allocator = allocator,
            .dispatcher = dispatcher,
            .device = device,
            .max_connections = max_connections,
            .flows = FlowMap.init(allocator),
        };
    }

    fn deinit(self: *FlowManager, io: Io) void {
        self.group.cancel(io);
        std.debug.assert(self.flows.count() == 0);
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
        flow.* = .{
            .key = segment.key,
            .inbound_tag = inbound_tag,
            .manager = self,
            .client_next = segment.sequence +% 1,
            .server_next = isn +% 1,
            .server_acked = isn,
            .client_window = segment.window,
        };
        flow.initializeQueue();
        self.flows.put(segment.key, flow) catch |err| {
            self.allocator.destroy(flow);
            self.mutex.unlock(io);
            return err;
        };
        self.mutex.unlock(io);

        flow.sendSynAck(io) catch |err| {
            self.removeAndDestroy(flow, io);
            return err;
        };
        self.group.concurrent(io, runFlow, .{ flow, io }) catch |err| {
            self.removeAndDestroy(flow, io);
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

    fn removeAndDestroy(self: *FlowManager, flow: *Flow, io: Io) void {
        self.mutex.lockUncancelable(io);
        _ = self.flows.remove(flow.key);
        self.mutex.unlock(io);
        flow.queue.close(io);
        self.allocator.destroy(flow);
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
    var manager = FlowManager.init(allocator, dispatcher, &device, settings.max_connections);
    defer manager.deinit(io);

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
    defer flow.manager.removeAndDestroy(flow, io);
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

    const Result = union(enum) {
        inbound: Io.Cancelable!void,
        outbound: Io.Cancelable!void,
    };
    var results: [2]Result = undefined;
    var select: Io.Select(Result) = .init(io, &results);
    defer select.cancelDiscard();
    select.concurrent(.inbound, inboundPump, .{ flow, pair[1], io }) catch return;
    select.concurrent(.outbound, outboundPump, .{ flow, pair[1], io }) catch return;
    _ = try select.await();
}

fn waitForPreface(flow: *Flow, buffer: *[session.max_preface_len]u8, io: Io) !usize {
    while (true) {
        const segment = try flow.queue.getOne(io);
        try flow.observeAck(&segment, io);
        if (segment.flags.rst) return error.ConnectionResetByPeer;
        if (segment.flags.syn) {
            try flow.sendSynAck(io);
            continue;
        }
        if (segment.payload_len == 0 and !segment.flags.fin) continue;
        if (!try flow.acceptClientData(&segment, io)) {
            try flow.sendAck(io);
            continue;
        }
        try flow.sendAck(io);
        if (segment.flags.fin and segment.payload_len == 0) return error.EndOfStream;
        @memcpy(buffer[0..segment.payload_len], segment.bytes());
        return segment.payload_len;
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
        try flow.observeAck(&segment, io);
        if (segment.flags.rst) return;
        if (segment.flags.syn) {
            flow.sendSynAck(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return,
            };
            continue;
        }
        if (segment.payload_len != 0 or segment.flags.fin) {
            if (!try flow.acceptClientData(&segment, io)) {
                flow.sendAck(io) catch |err| switch (err) {
                    error.Canceled => return error.Canceled,
                    else => return,
                };
                continue;
            }
            if (segment.payload_len != 0) {
                output.writeAll(segment.bytes()) catch return;
                output.flush() catch return;
            }
            flow.sendAck(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => return,
            };
            if (segment.flags.fin and !send_shutdown) {
                bridge.shutdown(io, .send) catch {};
                send_shutdown = true;
            }
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

fn sequenceAfter(a: u32, b: u32) bool {
    return @as(i32, @bitCast(a -% b)) > 0;
}

test "TCP sequence comparison handles wraparound" {
    try std.testing.expect(sequenceAfter(1, 0));
    try std.testing.expect(sequenceAfter(1, 0xfffffff0));
    try std.testing.expect(!sequenceAfter(0xfffffff0, 1));
}
