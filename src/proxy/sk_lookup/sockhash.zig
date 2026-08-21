const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;

const log = @import("../../log.zig");
const monitoring = @import("../../monitoring.zig");
const raw_reactor = @import("../../net/reactor.zig");

const linux = std.os.linux;
const BPF = linux.BPF;
const fd_t = std.posix.fd_t;
const posix = std.posix;

const sk_drop: i32 = 0;
const monitor_poll_ms = 1000;
const poll_rdhup: i16 = 0x2000;

pub const FallbackReason = enum {
    capacity,
    duplicate,
    socket_cookie,
    map_prepare,
    client_source,
    upstream_source,
    client_kick_payload,
    upstream_kick_payload,
};

pub const Admission = union(enum) {
    offloaded,
    fallback: FallbackReason,
    hybrid_raw: FallbackReason,
    terminal: FallbackReason,
};

pub const Owner = enum {
    generic,
    vless_vision,
    freedom,
};

pub const Peer = extern struct {
    peer_cookie: u64,
    flow_id: u64,
    direction: u32,
    reserved: u32 = 0,
};

pub const FlowState = extern struct {
    active: u32,
    reserved: u32 = 0,
};

pub const DirectionStats = extern struct {
    bytes: u64,
    last_seen_ns: u64,
    redirect_errors: u64,
};

pub const AggregateStats = extern struct {
    bytes: u64,
    packets: u64,
    redirect_errors: u64,
};

pub const Dataplane = struct {
    targets_fd: fd_t,
    sources_fd: fd_t,
    peers_fd: fd_t,
    state_fd: fd_t,
    stats_fd: fd_t,
    aggregate_fd: fd_t,
    parser_fd: fd_t,
    verdict_fd: fd_t,
    parser_link_fd: fd_t,
    verdict_link_fd: fd_t,

    pub fn init(max_flows: u32) !Dataplane {
        if (builtin.os.tag != .linux) return error.SockhashRequiresLinux;
        const socket_entries = std.math.mul(u32, max_flows, 2) catch return error.InvalidSockhashFlowLimit;

        const targets_fd = try createMap(.sockhash, @sizeOf(u64), @sizeOf(u32), socket_entries, "xz_sh_targets");
        errdefer closeFd(targets_fd);
        const sources_fd = try createMap(.sockhash, @sizeOf(u64), @sizeOf(u32), socket_entries, "xz_sh_sources");
        errdefer closeFd(sources_fd);
        const peers_fd = try createMap(.hash, @sizeOf(u64), @sizeOf(Peer), socket_entries, "xz_sh_peers");
        errdefer closeFd(peers_fd);
        const state_fd = try createMap(.hash, @sizeOf(u64), @sizeOf(FlowState), max_flows, "xz_sh_state");
        errdefer closeFd(state_fd);
        const stats_fd = try createMap(.hash, @sizeOf(u64), @sizeOf(DirectionStats), socket_entries, "xz_sh_stats");
        errdefer closeFd(stats_fd);
        const aggregate_fd = try createMap(.array, @sizeOf(u32), @sizeOf(AggregateStats), 1, "xz_sh_total");
        errdefer closeFd(aggregate_fd);

        const parser_instructions = parserProgram();
        const parser_fd = try loadProgram(
            &parser_instructions,
            .sk_skb,
            .sk_skb_stream_parser,
            "xz_sh_parser",
        );
        errdefer closeFd(parser_fd);
        const verdict_instructions = verdictProgram(targets_fd, peers_fd, state_fd, stats_fd, aggregate_fd);
        const verdict_fd = try loadProgram(
            &verdict_instructions,
            .sk_skb,
            .sk_skb_stream_verdict,
            "xz_sh_verdict",
        );
        errdefer closeFd(verdict_fd);

        const parser_link_fd = try createMapProgramLink(
            parser_fd,
            sources_fd,
            .sk_skb_stream_parser,
            "stream-parser",
            error.SockhashParserAttachFailed,
        );
        errdefer closeFd(parser_link_fd);
        const verdict_link_fd = try createMapProgramLink(
            verdict_fd,
            sources_fd,
            .sk_skb_stream_verdict,
            "stream-verdict",
            error.SockhashVerdictAttachFailed,
        );
        errdefer closeFd(verdict_link_fd);

        return .{
            .targets_fd = targets_fd,
            .sources_fd = sources_fd,
            .peers_fd = peers_fd,
            .state_fd = state_fd,
            .stats_fd = stats_fd,
            .aggregate_fd = aggregate_fd,
            .parser_fd = parser_fd,
            .verdict_fd = verdict_fd,
            .parser_link_fd = parser_link_fd,
            .verdict_link_fd = verdict_link_fd,
        };
    }

    pub fn deinit(self: *Dataplane) void {
        closeFd(self.verdict_link_fd);
        closeFd(self.parser_link_fd);
        closeFd(self.verdict_fd);
        closeFd(self.parser_fd);
        closeFd(self.stats_fd);
        closeFd(self.aggregate_fd);
        closeFd(self.state_fd);
        closeFd(self.peers_fd);
        closeFd(self.sources_fd);
        closeFd(self.targets_fd);
        self.* = undefined;
    }

    fn prepare(self: *Dataplane, flow_id: u64, client_cookie: u64, upstream_cookie: u64, client_fd: fd_t, upstream_fd: fd_t) !void {
        const active: FlowState = .{ .active = 1 };
        try updateNoExist(self.state_fd, &flow_id, &active);
        errdefer delete(self.state_fd, &flow_id);

        const zero: DirectionStats = .{ .bytes = 0, .last_seen_ns = 0, .redirect_errors = 0 };
        try updateNoExist(self.stats_fd, &client_cookie, &zero);
        errdefer delete(self.stats_fd, &client_cookie);
        try updateNoExist(self.stats_fd, &upstream_cookie, &zero);
        errdefer delete(self.stats_fd, &upstream_cookie);

        const client_peer: Peer = .{ .peer_cookie = upstream_cookie, .flow_id = flow_id, .direction = 0 };
        const upstream_peer: Peer = .{ .peer_cookie = client_cookie, .flow_id = flow_id, .direction = 1 };
        try updateNoExist(self.peers_fd, &client_cookie, &client_peer);
        errdefer delete(self.peers_fd, &client_cookie);
        try updateNoExist(self.peers_fd, &upstream_cookie, &upstream_peer);
        errdefer delete(self.peers_fd, &upstream_cookie);

        try updateSocketNoExist(self.targets_fd, client_cookie, client_fd);
        errdefer delete(self.targets_fd, &client_cookie);
        try updateSocketNoExist(self.targets_fd, upstream_cookie, upstream_fd);
    }

    fn insertSource(self: *Dataplane, cookie: u64, socket_fd: fd_t) !void {
        try updateSocketNoExist(self.sources_fd, cookie, socket_fd);
    }

    fn stats(self: *Dataplane, cookie: u64) !DirectionStats {
        var value: DirectionStats = undefined;
        try lookup(self.stats_fd, &cookie, &value);
        return value;
    }

    fn aggregateStats(self: *Dataplane) !AggregateStats {
        const key: u32 = 0;
        var value: AggregateStats = undefined;
        try lookup(self.aggregate_fd, &key, &value);
        return value;
    }

    fn cleanup(self: *Dataplane, flow_id: u64, client_cookie: u64, upstream_cookie: u64, source_mask: u2) void {
        if (source_mask & 1 != 0) delete(self.sources_fd, &client_cookie);
        if (source_mask & 2 != 0) delete(self.sources_fd, &upstream_cookie);
        const inactive: FlowState = .{ .active = 0 };
        updateExisting(self.state_fd, &flow_id, &inactive) catch {};
        delete(self.targets_fd, &client_cookie);
        delete(self.targets_fd, &upstream_cookie);
        delete(self.peers_fd, &client_cookie);
        delete(self.peers_fd, &upstream_cookie);
        delete(self.stats_fd, &client_cookie);
        delete(self.stats_fd, &upstream_cookie);
        delete(self.state_fd, &flow_id);
    }
};

const Flow = struct {
    client: net.Stream,
    upstream: net.Stream,
    client_cookie: u64,
    upstream_cookie: u64,
    flow_id: u64,
    source_mask: u2,
    owner: Owner,
    lifecycle: Lifecycle = .{},
    last_seen_ns: u64,
    client_bytes: u64 = 0,
    upstream_bytes: u64 = 0,
    next: ?*Flow = null,
};

const Side = enum { client, upstream };
const Observation = enum { none, eof, reset };

const LifecycleActions = packed struct {
    shutdown_client_send: bool = false,
    shutdown_upstream_send: bool = false,
    close: bool = false,

    fn merge(self: *LifecycleActions, other: LifecycleActions) void {
        self.shutdown_client_send = self.shutdown_client_send or other.shutdown_client_send;
        self.shutdown_upstream_send = self.shutdown_upstream_send or other.shutdown_upstream_send;
        self.close = self.close or other.close;
    }
};

const Lifecycle = struct {
    client_eof: bool = false,
    upstream_eof: bool = false,
    client_send_shutdown: bool = false,
    upstream_send_shutdown: bool = false,
    reset: bool = false,

    fn observe(self: *Lifecycle, side: Side, observation: Observation) LifecycleActions {
        if (observation == .reset) self.reset = true;
        if (observation == .eof) switch (side) {
            .client => self.client_eof = true,
            .upstream => self.upstream_eof = true,
        };

        var actions: LifecycleActions = .{};
        if (self.client_eof and !self.upstream_send_shutdown) {
            self.upstream_send_shutdown = true;
            actions.shutdown_upstream_send = true;
        }
        if (self.upstream_eof and !self.client_send_shutdown) {
            self.client_send_shutdown = true;
            actions.shutdown_client_send = true;
        }
        actions.close = self.reset or self.client_eof and self.upstream_eof;
        return actions;
    }
};

const InitialLifecycle = struct {
    state: Lifecycle,
    actions: LifecycleActions,
};

const HybridCleanup = struct {
    manager: *Manager,
    flow_id: u64,
    client_cookie: u64,
    upstream_cookie: u64,
    source_mask: u2,
};

pub const Manager = struct {
    allocator: std.mem.Allocator,
    io: Io,
    dataplane: Dataplane,
    max_flows: u32,
    idle_timeout_ns: u64,
    wake_fd: fd_t,
    poll_fds: []posix.pollfd,
    poll_flows: []*Flow,
    pending_head: std.atomic.Value(?*Flow) = .init(null),
    stopped: std.atomic.Value(bool) = .init(false),
    reserved_count: std.atomic.Value(u32) = .init(0),
    next_flow_id: std.atomic.Value(u64) = .init(1),
    active_count: usize = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        max_flows: u32,
        idle_timeout_seconds: u32,
    ) !Manager {
        if (builtin.os.tag != .linux) return error.SockhashRequiresLinux;
        if (max_flows == 0) return error.InvalidSockhashFlowLimit;
        const dataplane = try Dataplane.init(max_flows);
        errdefer {
            var owned = dataplane;
            owned.deinit();
        }
        const poll_fds = try allocator.alloc(posix.pollfd, @as(usize, max_flows) * 2 + 1);
        errdefer allocator.free(poll_fds);
        const poll_flows = try allocator.alloc(*Flow, max_flows);
        errdefer allocator.free(poll_flows);
        const wake_rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
        if (linux.errno(wake_rc) != .SUCCESS) return error.SockhashMonitorCreateFailed;

        monitoring.registry.sockhash_capacity.store(max_flows, .release);
        monitoring.registry.bpf_sockhash_parser_up.store(true, .release);
        monitoring.registry.bpf_sockhash_verdict_up.store(true, .release);
        return .{
            .allocator = allocator,
            .io = io,
            .dataplane = dataplane,
            .max_flows = max_flows,
            .idle_timeout_ns = @as(u64, idle_timeout_seconds) * std.time.ns_per_s,
            .wake_fd = @intCast(wake_rc),
            .poll_fds = poll_fds,
            .poll_flows = poll_flows,
        };
    }

    pub fn deinit(self: *Manager) void {
        monitoring.registry.sockhash_monitor_up.store(false, .release);
        monitoring.registry.bpf_sockhash_parser_up.store(false, .release);
        monitoring.registry.bpf_sockhash_verdict_up.store(false, .release);
        self.stop();
        self.closePendingList(self.pending_head.swap(null, .acquire));
        closeFd(self.wake_fd);
        self.allocator.free(self.poll_flows);
        self.allocator.free(self.poll_fds);
        self.dataplane.deinit();
        self.* = undefined;
    }

    pub fn stop(self: *Manager) void {
        if (self.stopped.swap(true, .release)) return;
        self.wake();
    }

    pub fn admit(
        self: *Manager,
        client: net.Stream,
        upstream: net.Stream,
        reactor: *raw_reactor.Reactor,
    ) Admission {
        return self.admitOwned(client, upstream, reactor, .generic);
    }

    pub fn admitOwned(
        self: *Manager,
        client: net.Stream,
        upstream: net.Stream,
        reactor: *raw_reactor.Reactor,
        owner: Owner,
    ) Admission {
        const result = self.admitOwnedInner(client, upstream, reactor, owner);
        recordAdmission(owner, result, monotonicNowNs(self.io));
        return result;
    }

    fn admitOwnedInner(
        self: *Manager,
        client: net.Stream,
        upstream: net.Stream,
        reactor: *raw_reactor.Reactor,
        owner: Owner,
    ) Admission {
        if (!self.reserve()) return .{ .fallback = .capacity };
        var reservation_owned = true;
        defer if (reservation_owned) self.releaseReservation();

        const client_copy = duplicateStream(client) catch return .{ .fallback = .duplicate };
        defer client_copy.close(self.io);
        const upstream_copy = duplicateStream(upstream) catch return .{ .fallback = .duplicate };
        defer upstream_copy.close(self.io);
        setNonBlocking(client_copy.socket.handle) catch return .{ .fallback = .duplicate };
        setNonBlocking(upstream_copy.socket.handle) catch return .{ .fallback = .duplicate };

        const client_cookie = socketCookie(client_copy.socket.handle) catch return .{ .fallback = .socket_cookie };
        const upstream_cookie = socketCookie(upstream_copy.socket.handle) catch return .{ .fallback = .socket_cookie };
        if (!cookiesUsable(client_cookie, upstream_cookie))
            return .{ .fallback = .socket_cookie };

        const flow_id = self.next_flow_id.fetchAdd(1, .monotonic);
        self.dataplane.prepare(
            flow_id,
            client_cookie,
            upstream_cookie,
            client_copy.socket.handle,
            upstream_copy.socket.handle,
        ) catch return .{ .fallback = .map_prepare };
        var prepared = true;
        var source_mask: u2 = 0;
        defer if (prepared) self.dataplane.cleanup(flow_id, client_cookie, upstream_cookie, source_mask);

        self.dataplane.insertSource(client_cookie, client_copy.socket.handle) catch
            return .{ .fallback = .client_source };
        source_mask |= 1;
        const client_kick = kickSource(client_copy.socket.handle) catch .payload;
        if (!kickAllowsCutover(client_kick)) {
            resetPeer(client_copy.socket.handle, upstream_copy.socket.handle);
            return .{ .terminal = .client_kick_payload };
        }

        self.dataplane.insertSource(upstream_cookie, upstream_copy.socket.handle) catch
            return self.adoptHybrid(
                reactor,
                client,
                upstream,
                flow_id,
                client_cookie,
                upstream_cookie,
                source_mask,
                &prepared,
                &reservation_owned,
                .upstream_source,
            );
        source_mask |= 2;
        const upstream_kick = kickSource(upstream_copy.socket.handle) catch .payload;
        if (!kickAllowsCutover(upstream_kick)) {
            resetPeer(client_copy.socket.handle, upstream_copy.socket.handle);
            return .{ .terminal = .upstream_kick_payload };
        }
        const initial_lifecycle = lifecycleAfterKicks(client_kick, upstream_kick);

        const flow = self.allocator.create(Flow) catch {
            resetPeer(client_copy.socket.handle, upstream_copy.socket.handle);
            return .{ .terminal = .capacity };
        };
        const manager_client = duplicateStream(client_copy) catch {
            self.allocator.destroy(flow);
            resetPeer(client_copy.socket.handle, upstream_copy.socket.handle);
            return .{ .terminal = .duplicate };
        };
        const manager_upstream = duplicateStream(upstream_copy) catch {
            manager_client.close(self.io);
            self.allocator.destroy(flow);
            resetPeer(client_copy.socket.handle, upstream_copy.socket.handle);
            return .{ .terminal = .duplicate };
        };
        flow.* = .{
            .client = manager_client,
            .upstream = manager_upstream,
            .client_cookie = client_cookie,
            .upstream_cookie = upstream_cookie,
            .flow_id = flow_id,
            .source_mask = source_mask,
            .owner = owner,
            .lifecycle = initial_lifecycle.state,
            .last_seen_ns = monotonicNowNs(self.io),
        };
        // Both receive queues have passed through the parser/verdict path at
        // this point. Propagate FIN only now, after any pre-admission payload
        // has been redirected, but before publishing the flow to the monitor.
        if (initial_lifecycle.actions.shutdown_upstream_send)
            shutdownSend(manager_upstream.socket.handle);
        if (initial_lifecycle.actions.shutdown_client_send)
            shutdownSend(manager_client.socket.handle);
        prepared = false;
        reservation_owned = false;
        self.pushPending(flow);
        self.wake();
        return .offloaded;
    }

    fn adoptHybrid(
        self: *Manager,
        reactor: *raw_reactor.Reactor,
        client: net.Stream,
        upstream: net.Stream,
        flow_id: u64,
        client_cookie: u64,
        upstream_cookie: u64,
        source_mask: u2,
        prepared: *bool,
        reservation_owned: *bool,
        reason: FallbackReason,
    ) Admission {
        const cleanup = self.allocator.create(HybridCleanup) catch {
            resetPeer(client.socket.handle, upstream.socket.handle);
            return .{ .terminal = reason };
        };
        cleanup.* = .{
            .manager = self,
            .flow_id = flow_id,
            .client_cookie = client_cookie,
            .upstream_cookie = upstream_cookie,
            .source_mask = source_mask,
        };
        reactor.adoptDuplicateWithCleanup(client, upstream, .{
            .context = cleanup,
            .callback = releaseHybrid,
            .health_callback = hybridHealthy,
        }) catch {
            self.allocator.destroy(cleanup);
            resetPeer(client.socket.handle, upstream.socket.handle);
            return .{ .terminal = reason };
        };
        prepared.* = false;
        reservation_owned.* = false;
        return .{ .hybrid_raw = reason };
    }

    pub fn run(self: *Manager) Io.Cancelable!void {
        monitoring.registry.sockhash_monitor_up.store(true, .release);
        defer monitoring.registry.sockhash_monitor_up.store(false, .release);
        var active_head: ?*Flow = null;
        defer {
            self.closeActiveList(active_head);
            self.closePendingList(self.pending_head.swap(null, .acquire));
        }

        while (true) {
            self.takePending(&active_head);
            if (self.stopped.load(.acquire)) return;
            self.poll_fds[0] = .{ .fd = self.wake_fd, .events = posix.POLL.IN, .revents = 0 };
            var count: usize = 0;
            var current = active_head;
            while (current) |flow| : (current = flow.next) {
                self.poll_flows[count] = flow;
                self.poll_fds[count * 2 + 1] = sourcePollFd(
                    flow.client.socket.handle,
                    flow.lifecycle.client_eof,
                );
                self.poll_fds[count * 2 + 2] = sourcePollFd(
                    flow.upstream.socket.handle,
                    flow.lifecycle.upstream_eof,
                );
                count += 1;
            }

            _ = posix.poll(self.poll_fds[0 .. count * 2 + 1], monitor_poll_ms) catch continue;
            try Io.checkCancel(self.io);
            if (self.poll_fds[0].revents & posix.POLL.IN != 0) self.drainWake();
            if (self.stopped.load(.acquire)) return;

            const now = monotonicNowNs(self.io);
            var index: usize = 0;
            while (index < count) : (index += 1) {
                const flow = self.poll_flows[index];
                self.serviceFlow(
                    flow,
                    self.poll_fds[index * 2 + 1].revents,
                    self.poll_fds[index * 2 + 2].revents,
                );
            }

            var link = &active_head;
            while (link.*) |flow| {
                if (flow.lifecycle.reset or
                    flow.lifecycle.client_eof and flow.lifecycle.upstream_eof or
                    idleExpired(flow.last_seen_ns, now, self.idle_timeout_ns))
                {
                    link.* = flow.next;
                    self.closeFlow(flow);
                } else {
                    link = &flow.next;
                }
            }
            if (self.dataplane.aggregateStats()) |stats| {
                monitoring.registry.sockhash_kernel_bytes.store(stats.bytes, .release);
                monitoring.registry.sockhash_packets.store(stats.packets, .release);
                monitoring.registry.sockhash_redirect_errors.store(stats.redirect_errors, .release);
            } else |_| {}
        }
    }

    pub fn refreshMonitoring(self: *Manager) void {
        const stats = self.dataplane.aggregateStats() catch return;
        monitoring.registry.sockhash_kernel_bytes.store(stats.bytes, .release);
        monitoring.registry.sockhash_packets.store(stats.packets, .release);
        monitoring.registry.sockhash_redirect_errors.store(stats.redirect_errors, .release);
    }

    fn serviceFlow(self: *Manager, flow: *Flow, client_events: i16, upstream_events: i16) void {
        const client_stats = self.dataplane.stats(flow.client_cookie) catch {
            _ = flow.lifecycle.observe(.client, .reset);
            return;
        };
        const upstream_stats = self.dataplane.stats(flow.upstream_cookie) catch {
            _ = flow.lifecycle.observe(.upstream, .reset);
            return;
        };
        if (client_stats.redirect_errors != 0 or upstream_stats.redirect_errors != 0) {
            _ = flow.lifecycle.observe(.client, .reset);
            return;
        }
        flow.client_bytes = client_stats.bytes;
        flow.upstream_bytes = upstream_stats.bytes;
        flow.last_seen_ns = @max(flow.last_seen_ns, @max(client_stats.last_seen_ns, upstream_stats.last_seen_ns));

        const client_actions = flow.lifecycle.observe(.client, inspectSource(flow.client.socket.handle, client_events));
        const upstream_actions = flow.lifecycle.observe(.upstream, inspectSource(flow.upstream.socket.handle, upstream_events));
        if (client_actions.shutdown_upstream_send or upstream_actions.shutdown_upstream_send) {
            shutdownSend(flow.upstream.socket.handle);
        }
        if (client_actions.shutdown_client_send or upstream_actions.shutdown_client_send) {
            shutdownSend(flow.client.socket.handle);
        }
    }

    fn pushPending(self: *Manager, flow: *Flow) void {
        var head = self.pending_head.load(.monotonic);
        while (true) {
            flow.next = head;
            head = self.pending_head.cmpxchgWeak(head, flow, .release, .monotonic) orelse return;
        }
    }

    fn takePending(self: *Manager, active_head: *?*Flow) void {
        var pending = self.pending_head.swap(null, .acquire);
        while (pending) |flow| {
            const next = flow.next;
            flow.next = active_head.*;
            active_head.* = flow;
            self.active_count += 1;
            pending = next;
        }
    }

    fn closeActiveList(self: *Manager, head: ?*Flow) void {
        var current = head;
        while (current) |flow| {
            const next = flow.next;
            self.closeFlow(flow);
            current = next;
        }
    }

    fn closePendingList(self: *Manager, head: ?*Flow) void {
        var current = head;
        while (current) |flow| {
            const next = flow.next;
            self.closeFlow(flow);
            current = next;
        }
    }

    fn closeFlow(self: *Manager, flow: *Flow) void {
        if (flow.lifecycle.reset) resetPeer(flow.client.socket.handle, flow.upstream.socket.handle);
        const client_stats: DirectionStats = self.dataplane.stats(flow.client_cookie) catch .{
            .bytes = flow.client_bytes,
            .last_seen_ns = flow.last_seen_ns,
            .redirect_errors = 1,
        };
        const upstream_stats: DirectionStats = self.dataplane.stats(flow.upstream_cookie) catch .{
            .bytes = flow.upstream_bytes,
            .last_seen_ns = flow.last_seen_ns,
            .redirect_errors = 1,
        };
        log.info(
            "sockhash-close owner={s} flow={d} client_bytes={d} upstream_bytes={d} errors={d} reset={}\n",
            .{
                @tagName(flow.owner),
                flow.flow_id,
                client_stats.bytes,
                upstream_stats.bytes,
                client_stats.redirect_errors +| upstream_stats.redirect_errors,
                flow.lifecycle.reset,
            },
        );
        monitoring.registry.offloadClosed(
            monitoringOwner(flow.owner),
            client_stats.bytes,
            upstream_stats.bytes,
            client_stats.redirect_errors +| upstream_stats.redirect_errors,
            monotonicNowNs(self.io),
        );
        self.dataplane.cleanup(
            flow.flow_id,
            flow.client_cookie,
            flow.upstream_cookie,
            flow.source_mask,
        );
        flow.client.close(self.io);
        flow.upstream.close(self.io);
        self.allocator.destroy(flow);
        self.releaseReservation();
        if (self.active_count > 0) self.active_count -= 1;
    }

    fn reserve(self: *Manager) bool {
        var count = self.reserved_count.load(.monotonic);
        while (count < self.max_flows) {
            count = self.reserved_count.cmpxchgWeak(count, count + 1, .acquire, .monotonic) orelse return true;
        }
        return false;
    }

    fn releaseReservation(self: *Manager) void {
        _ = self.reserved_count.fetchSub(1, .release);
    }

    fn wake(self: *Manager) void {
        var value: u64 = 1;
        while (true) {
            const rc = linux.write(self.wake_fd, @ptrCast(&value), @sizeOf(u64));
            switch (linux.errno(rc)) {
                .SUCCESS, .AGAIN => return,
                .INTR => continue,
                else => return,
            }
        }
    }

    fn drainWake(self: *Manager) void {
        var value: u64 = undefined;
        while (true) {
            const rc = linux.read(self.wake_fd, @ptrCast(&value), @sizeOf(u64));
            switch (linux.errno(rc)) {
                .SUCCESS, .AGAIN => return,
                .INTR => continue,
                else => return,
            }
        }
    }
};

fn recordAdmission(owner: Owner, admission: Admission, now_ns: u64) void {
    const metric_owner = monitoringOwner(owner);
    switch (admission) {
        .offloaded => monitoring.registry.offload(metric_owner, .offloaded, .none, now_ns),
        .fallback => |reason| monitoring.registry.offload(metric_owner, .raw_fallback, monitoringReason(reason), now_ns),
        .hybrid_raw => |reason| monitoring.registry.offload(metric_owner, .hybrid_raw, monitoringReason(reason), now_ns),
        .terminal => |reason| monitoring.registry.offload(metric_owner, .failed_closed, monitoringReason(reason), now_ns),
    }
}

fn monitoringOwner(owner: Owner) monitoring.Owner {
    return switch (owner) {
        .freedom => .freedom,
        .vless_vision => .vless_vision,
        .generic => .generic,
    };
}

fn monitoringReason(reason: FallbackReason) monitoring.FallbackReason {
    return switch (reason) {
        inline else => |value| @enumFromInt(@as(usize, @intFromEnum(value)) + 1),
    };
}

fn releaseHybrid(context: *anyopaque) void {
    const cleanup: *HybridCleanup = @ptrCast(@alignCast(context));
    const manager = cleanup.manager;
    manager.dataplane.cleanup(
        cleanup.flow_id,
        cleanup.client_cookie,
        cleanup.upstream_cookie,
        cleanup.source_mask,
    );
    manager.releaseReservation();
    manager.allocator.destroy(cleanup);
}

fn hybridHealthy(context: *anyopaque) bool {
    const cleanup: *HybridCleanup = @ptrCast(@alignCast(context));
    if (cleanup.source_mask & 1 != 0) {
        const stats = cleanup.manager.dataplane.stats(cleanup.client_cookie) catch return false;
        if (stats.redirect_errors != 0) return false;
    }
    if (cleanup.source_mask & 2 != 0) {
        const stats = cleanup.manager.dataplane.stats(cleanup.upstream_cookie) catch return false;
        if (stats.redirect_errors != 0) return false;
    }
    return true;
}

const Kick = enum { redirected, eof, payload };

fn kickAllowsCutover(result: Kick) bool {
    return result != .payload;
}

fn lifecycleAfterKicks(client_kick: Kick, upstream_kick: Kick) InitialLifecycle {
    var state: Lifecycle = .{};
    var actions: LifecycleActions = .{};
    if (client_kick == .eof) actions.merge(state.observe(.client, .eof));
    if (upstream_kick == .eof) actions.merge(state.observe(.upstream, .eof));
    return .{ .state = state, .actions = actions };
}

fn cookiesUsable(client_cookie: u64, upstream_cookie: u64) bool {
    return client_cookie != 0 and upstream_cookie != 0 and client_cookie != upstream_cookie;
}

fn kickSource(fd: fd_t) !Kick {
    var byte: [1]u8 = undefined;
    while (true) {
        const rc = linux.recvfrom(fd, &byte, byte.len, linux.MSG.PEEK | linux.MSG.DONTWAIT, null, null);
        return switch (linux.errno(rc)) {
            .SUCCESS => if (rc == 0) .eof else .payload,
            .AGAIN => .redirected,
            .INTR => continue,
            else => error.SockhashKickFailed,
        };
    }
}

fn inspectSource(fd: fd_t, events: i16) Observation {
    if (events & (posix.POLL.ERR | posix.POLL.NVAL) != 0) {
        return .reset;
    }
    if (events & (posix.POLL.IN | posix.POLL.HUP | poll_rdhup) == 0) return .none;
    const result = kickSource(fd) catch {
        return .reset;
    };
    return switch (result) {
        .redirected => .none,
        .eof => .eof,
        .payload => .reset,
    };
}

fn sourcePollFd(fd: fd_t, eof: bool) posix.pollfd {
    // POLLIN and POLLRDHUP are level-triggered at EOF. Once that FIN has been
    // propagated, leaving the descriptor in poll makes the manager wake
    // continuously until the opposite half closes. A negative descriptor is
    // explicitly ignored by poll while ownership of the socket is retained.
    return .{
        .fd = if (eof) -1 else fd,
        .events = if (eof) 0 else posix.POLL.IN | poll_rdhup,
        .revents = 0,
    };
}

fn idleExpired(last_seen_ns: u64, now_ns: u64, timeout_ns: u64) bool {
    return now_ns -| last_seen_ns >= timeout_ns;
}

const CleanupOwnership = struct {
    released: bool = false,

    fn release(self: *CleanupOwnership) bool {
        if (self.released) return false;
        self.released = true;
        return true;
    }
};

fn socketCookie(fd: fd_t) !u64 {
    var cookie: u64 = 0;
    var length: linux.socklen_t = @sizeOf(u64);
    const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.COOKIE, @ptrCast(&cookie), &length);
    if (linux.errno(rc) != .SUCCESS or length != @sizeOf(u64)) return error.SockhashSocketCookieFailed;
    return cookie;
}

fn duplicateStream(stream: net.Stream) !net.Stream {
    const rc = linux.dup(stream.socket.handle);
    if (linux.errno(rc) != .SUCCESS) return error.SystemResources;
    return .{ .socket = .{ .handle = @intCast(rc), .address = stream.socket.address } };
}

fn setNonBlocking(fd: fd_t) !void {
    const get_rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(get_rc) != .SUCCESS) return error.Unexpected;
    const nonblock = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    const set_rc = posix.system.fcntl(fd, posix.F.SETFL, get_rc | nonblock);
    if (posix.errno(set_rc) != .SUCCESS) return error.Unexpected;
}

fn monotonicNowNs(io: Io) u64 {
    return @intCast(Io.Timestamp.now(io, .awake).nanoseconds);
}

fn shutdownSend(fd: fd_t) void {
    _ = linux.shutdown(fd, linux.SHUT.WR);
}

fn resetPeer(first_fd: fd_t, second_fd: fd_t) void {
    const linger: linux.linger = .{ .onoff = 1, .linger = 0 };
    _ = linux.setsockopt(first_fd, linux.SOL.SOCKET, linux.SO.LINGER, @ptrCast(&linger), @sizeOf(linux.linger));
    _ = linux.setsockopt(second_fd, linux.SOL.SOCKET, linux.SO.LINGER, @ptrCast(&linger), @sizeOf(linux.linger));
}

fn createMap(map_type: BPF.MapType, key_size: u32, value_size: u32, max_entries: u32, name: []const u8) !fd_t {
    var attr: BPF.Attr = .{ .map_create = std.mem.zeroes(BPF.MapCreateAttr) };
    attr.map_create.map_type = @intFromEnum(map_type);
    attr.map_create.key_size = key_size;
    attr.map_create.value_size = value_size;
    attr.map_create.max_entries = max_entries;
    @memcpy(attr.map_create.map_name[0..name.len], name);
    return fdResult(linux.bpf(.map_create, &attr, @sizeOf(BPF.MapCreateAttr)), error.SockhashMapCreateFailed);
}

fn updateNoExist(map_fd: fd_t, key: anytype, value: anytype) !void {
    try update(map_fd, std.mem.asBytes(key), std.mem.asBytes(value), BPF.NOEXIST);
}

fn updateExisting(map_fd: fd_t, key: anytype, value: anytype) !void {
    try update(map_fd, std.mem.asBytes(key), std.mem.asBytes(value), BPF.EXIST);
}

fn updateSocketNoExist(map_fd: fd_t, cookie: u64, socket_fd: fd_t) !void {
    const value: u32 = @intCast(socket_fd);
    try update(map_fd, std.mem.asBytes(&cookie), std.mem.asBytes(&value), BPF.NOEXIST);
}

fn update(map_fd: fd_t, key: []const u8, value: []const u8, flags: u64) !void {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key.ptr);
    attr.map_elem.result.value = @intFromPtr(value.ptr);
    attr.map_elem.flags = flags;
    const rc = linux.bpf(.map_update_elem, &attr, @sizeOf(BPF.MapElemAttr));
    if (linux.errno(rc) != .SUCCESS) return error.SockhashMapUpdateFailed;
}

fn lookup(map_fd: fd_t, key: anytype, value: anytype) !void {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key);
    attr.map_elem.result.value = @intFromPtr(value);
    const rc = linux.bpf(.map_lookup_elem, &attr, @sizeOf(BPF.MapElemAttr));
    if (linux.errno(rc) != .SUCCESS) return error.SockhashMapLookupFailed;
}

fn delete(map_fd: fd_t, key: anytype) void {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key);
    const rc = linux.bpf(.map_delete_elem, &attr, @sizeOf(BPF.MapElemAttr));
    switch (linux.errno(rc)) {
        .SUCCESS, .NOENT => {},
        else => |err| log.warn("SOCKHASH BPF map delete failed: {s}\n", .{@tagName(err)}),
    }
}

fn loadProgram(instructions: []const BPF.Insn, program_type: BPF.ProgType, attach_type: BPF.AttachType, name: []const u8) !fd_t {
    var verifier_log: [64 * 1024]u8 = @splat(0);
    const license = "GPL\x00";
    var attr: BPF.Attr = .{ .prog_load = std.mem.zeroes(BPF.ProgLoadAttr) };
    attr.prog_load.prog_type = @intFromEnum(program_type);
    attr.prog_load.insn_cnt = @intCast(instructions.len);
    attr.prog_load.insns = @intFromPtr(instructions.ptr);
    attr.prog_load.license = @intFromPtr(license.ptr);
    attr.prog_load.log_level = 1;
    attr.prog_load.log_size = verifier_log.len;
    attr.prog_load.log_buf = @intFromPtr(&verifier_log);
    attr.prog_load.expected_attach_type = @intFromEnum(attach_type);
    @memcpy(attr.prog_load.prog_name[0..name.len], name);
    const rc = linux.bpf(.prog_load, &attr, @sizeOf(BPF.ProgLoadAttr));
    if (linux.errno(rc) != .SUCCESS) {
        verifier_log[verifier_log.len - 1] = 0;
        const length = std.mem.indexOfScalar(u8, &verifier_log, 0) orelse verifier_log.len;
        log.warn("SOCKHASH BPF verifier rejected {s}: {s}\n", .{ name, verifier_log[0..length] });
        return error.SockhashProgramLoadFailed;
    }
    return @intCast(rc);
}

fn createMapProgramLink(
    program_fd: fd_t,
    map_fd: fd_t,
    attach_type: BPF.AttachType,
    stage: []const u8,
    failure: anyerror,
) !fd_t {
    var attr: BPF.Attr = .{ .link_create = std.mem.zeroes(BPF.LinkCreateAttr) };
    attr.link_create.prog_fd = program_fd;
    attr.link_create.target_fd = map_fd;
    attr.link_create.attach_type = @intFromEnum(attach_type);
    const rc = linux.bpf(.link_create, &attr, @sizeOf(BPF.LinkCreateAttr));
    const err = linux.errno(rc);
    if (err != .SUCCESS) {
        log.warn(
            "SOCKHASH BPF {s} link create failed: errno={s}({d}), attach_type={d}, program_fd={d}, map_fd={d}\n",
            .{ stage, @tagName(err), @intFromEnum(err), @intFromEnum(attach_type), program_fd, map_fd },
        );
        if (err == .OPNOTSUPP and attach_type == .sk_skb_stream_parser) {
            log.warn("SOCKHASH stream parser requires CONFIG_BPF_STREAM_PARSER in the target kernel\n", .{});
        }
        return failure;
    }
    return @intCast(rc);
}

fn fdResult(rc: usize, failure: anyerror) !fd_t {
    if (linux.errno(rc) != .SUCCESS) return failure;
    return @intCast(rc);
}

fn closeFd(fd: fd_t) void {
    _ = linux.close(fd);
}

fn parserProgram() [2]BPF.Insn {
    return .{
        BPF.Insn.ldx(.word, .r0, .r1, 0),
        BPF.Insn.exit(),
    };
}

fn xaddAt(dst: BPF.Insn.Reg, offset: i16, src: BPF.Insn.Reg) BPF.Insn {
    var instruction = BPF.Insn.xadd(dst, src);
    instruction.off = offset;
    return instruction;
}

fn verdictProgram(targets_fd: fd_t, peers_fd: fd_t, state_fd: fd_t, stats_fd: fd_t, aggregate_fd: fd_t) [62]BPF.Insn {
    return .{
        BPF.Insn.mov(.r6, .r1),
        BPF.Insn.call(.get_socket_cookie),
        BPF.Insn.jeq(.r0, 0, 54),
        BPF.Insn.stx(.double_word, .r10, -8, .r0),
        BPF.Insn.ld_map_fd1(.r1, stats_fd),
        BPF.Insn.ld_map_fd2(stats_fd),
        BPF.Insn.mov(.r2, .r10),
        BPF.Insn.add(.r2, -8),
        BPF.Insn.call(.map_lookup_elem),
        BPF.Insn.jeq(.r0, 0, 47),
        BPF.Insn.mov(.r8, .r0),
        BPF.Insn.ldx(.word, .r9, .r6, 0),
        xaddAt(.r8, 0, .r9),
        BPF.Insn.call(.ktime_get_ns),
        BPF.Insn.stx(.double_word, .r8, 8, .r0),
        BPF.Insn.st(.word, .r10, -32, 0),
        BPF.Insn.ld_map_fd1(.r1, aggregate_fd),
        BPF.Insn.ld_map_fd2(aggregate_fd),
        BPF.Insn.mov(.r2, .r10),
        BPF.Insn.add(.r2, -32),
        BPF.Insn.call(.map_lookup_elem),
        BPF.Insn.jeq(.r0, 0, 36),
        BPF.Insn.mov(.r7, .r0),
        BPF.Insn.ldx(.word, .r9, .r6, 0),
        xaddAt(.r7, 0, .r9),
        BPF.Insn.mov(.r9, 1),
        xaddAt(.r7, 8, .r9),
        BPF.Insn.ld_map_fd1(.r1, peers_fd),
        BPF.Insn.ld_map_fd2(peers_fd),
        BPF.Insn.mov(.r2, .r10),
        BPF.Insn.add(.r2, -8),
        BPF.Insn.call(.map_lookup_elem),
        BPF.Insn.jeq(.r0, 0, 20),
        BPF.Insn.ldx(.double_word, .r9, .r0, 8),
        BPF.Insn.stx(.double_word, .r10, -16, .r9),
        BPF.Insn.ldx(.double_word, .r9, .r0, 0),
        BPF.Insn.stx(.double_word, .r10, -24, .r9),
        BPF.Insn.ld_map_fd1(.r1, state_fd),
        BPF.Insn.ld_map_fd2(state_fd),
        BPF.Insn.mov(.r2, .r10),
        BPF.Insn.add(.r2, -16),
        BPF.Insn.call(.map_lookup_elem),
        BPF.Insn.jeq(.r0, 0, 10),
        BPF.Insn.ldx(.word, .r1, .r0, 0),
        BPF.Insn.jne(.r1, 1, 8),
        BPF.Insn.ld_map_fd1(.r2, targets_fd),
        BPF.Insn.ld_map_fd2(targets_fd),
        BPF.Insn.mov(.r1, .r6),
        BPF.Insn.mov(.r3, .r10),
        BPF.Insn.add(.r3, -24),
        BPF.Insn.mov(.r4, 0),
        BPF.Insn.call(.sk_redirect_hash),
        BPF.Insn.jne(.r0, sk_drop, 4),
        BPF.Insn.mov(.r9, 1),
        xaddAt(.r7, 16, .r9),
        xaddAt(.r8, 16, .r9),
        BPF.Insn.mov(.r0, sk_drop),
        BPF.Insn.exit(),
        BPF.Insn.mov(.r9, 1),
        xaddAt(.r8, 16, .r9),
        BPF.Insn.mov(.r0, sk_drop),
        BPF.Insn.exit(),
    };
}

test "SOCKHASH parser and verdict have stable instruction layout" {
    const parser = parserProgram();
    try std.testing.expectEqual(@as(usize, 2), parser.len);
    try std.testing.expectEqual(BPF.Insn.exit(), parser[1]);

    const verdict = verdictProgram(10, 11, 12, 13, 14);
    try std.testing.expectEqual(@as(usize, 62), verdict.len);
    try std.testing.expectEqual(BPF.Insn.call(.get_socket_cookie), verdict[1]);
    try std.testing.expectEqual(BPF.Insn.call(.sk_redirect_hash), verdict[51]);
    try std.testing.expectEqual(BPF.Insn.exit(), verdict[57]);
    try std.testing.expectEqual(BPF.Insn.exit(), verdict[61]);
    const final_exit: isize = 57;
    for ([_]usize{ 2, 9 }) |index|
        try std.testing.expectEqual(final_exit, @as(isize, @intCast(index + 1)) + verdict[index].off);
    const per_stats_error_path: isize = 58;
    try std.testing.expectEqual(per_stats_error_path, @as(isize, 22) + verdict[21].off);
    const error_path: isize = 53;
    for ([_]usize{ 32, 42, 44 }) |index|
        try std.testing.expectEqual(error_path, @as(isize, @intCast(index + 1)) + verdict[index].off);
    try std.testing.expectEqual(final_exit, @as(isize, 53) + verdict[52].off);
}

test "SOCKHASH link create uses the stable Linux UAPI fields" {
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(BPF.LinkCreateAttr));
    try std.testing.expectEqual(@as(u32, 4), @intFromEnum(BPF.AttachType.sk_skb_stream_parser));
    try std.testing.expectEqual(@as(u32, 5), @intFromEnum(BPF.AttachType.sk_skb_stream_verdict));

    var attr: BPF.Attr = .{ .link_create = std.mem.zeroes(BPF.LinkCreateAttr) };
    attr.link_create.prog_fd = 11;
    attr.link_create.target_fd = 12;
    attr.link_create.attach_type = @intFromEnum(BPF.AttachType.sk_skb_stream_parser);
    try std.testing.expectEqual(@as(fd_t, 11), attr.link_create.prog_fd);
    try std.testing.expectEqual(@as(fd_t, 12), attr.link_create.target_fd);
    try std.testing.expectEqual(@as(u32, 4), attr.link_create.attach_type);
    try std.testing.expectEqual(@as(u32, 0), attr.link_create.flags);
}

test "duplicate and zero socket cookies are rejected before map mutation" {
    try std.testing.expect(!cookiesUsable(0, 2));
    try std.testing.expect(!cookiesUsable(1, 0));
    try std.testing.expect(!cookiesUsable(7, 7));
    try std.testing.expect(cookiesUsable(7, 8));
}

test "payload returned by the post-attach kick is fail-closed" {
    try std.testing.expect(kickAllowsCutover(.redirected));
    try std.testing.expect(kickAllowsCutover(.eof));
    try std.testing.expect(!kickAllowsCutover(.payload));
}

test "bounded flow reservations fall back at capacity" {
    var manager: Manager = undefined;
    manager.max_flows = 1;
    manager.reserved_count = .init(0);
    try std.testing.expect(manager.reserve());
    try std.testing.expect(!manager.reserve());
    manager.releaseReservation();
    try std.testing.expect(manager.reserve());
    manager.releaseReservation();
}

test "client-only and upstream-only hybrid cutovers preserve byte order" {
    const Model = struct {
        source_mask: u2 = 0,
        local_client: [64]u8 = undefined,
        local_client_len: usize = 0,
        local_upstream: [64]u8 = undefined,
        local_upstream_len: usize = 0,
        delivered_client: [64]u8 = undefined,
        delivered_client_len: usize = 0,
        delivered_upstream: [64]u8 = undefined,
        delivered_upstream_len: usize = 0,

        fn receive(self: *@This(), comptime from_client: bool, bytes: []const u8) void {
            const programmed = self.source_mask & (if (from_client) 1 else 2) != 0;
            if (programmed) {
                self.deliver(from_client, bytes);
            } else if (from_client) {
                append(&self.local_client, &self.local_client_len, bytes);
            } else {
                append(&self.local_upstream, &self.local_upstream_len, bytes);
            }
        }

        fn kick(self: *@This(), comptime from_client: bool) void {
            if (from_client) {
                self.deliver(true, self.local_client[0..self.local_client_len]);
                self.local_client_len = 0;
            } else {
                self.deliver(false, self.local_upstream[0..self.local_upstream_len]);
                self.local_upstream_len = 0;
            }
        }

        fn rawDrain(self: *@This(), comptime from_client: bool) void {
            self.kick(from_client);
        }

        fn deliver(self: *@This(), comptime from_client: bool, bytes: []const u8) void {
            if (from_client) {
                append(&self.delivered_upstream, &self.delivered_upstream_len, bytes);
            } else {
                append(&self.delivered_client, &self.delivered_client_len, bytes);
            }
        }

        fn append(storage: *[64]u8, length: *usize, bytes: []const u8) void {
            @memcpy(storage[length.*..][0..bytes.len], bytes);
            length.* += bytes.len;
        }
    };

    var client_only: Model = .{};
    client_only.receive(true, "pre-");
    client_only.source_mask = 1;
    client_only.kick(true);
    client_only.receive(true, "post");
    client_only.receive(false, "reply-");
    client_only.rawDrain(false);
    client_only.receive(false, "tail");
    client_only.rawDrain(false);
    try std.testing.expectEqualStrings("pre-post", client_only.delivered_upstream[0..client_only.delivered_upstream_len]);
    try std.testing.expectEqualStrings("reply-tail", client_only.delivered_client[0..client_only.delivered_client_len]);

    var upstream_only: Model = .{};
    upstream_only.receive(false, "pre-");
    upstream_only.source_mask = 2;
    upstream_only.kick(false);
    upstream_only.receive(false, "post");
    upstream_only.receive(true, "request-");
    upstream_only.rawDrain(true);
    upstream_only.receive(true, "tail");
    upstream_only.rawDrain(true);
    try std.testing.expectEqualStrings("pre-post", upstream_only.delivered_client[0..upstream_only.delivered_client_len]);
    try std.testing.expectEqualStrings("request-tail", upstream_only.delivered_upstream[0..upstream_only.delivered_upstream_len]);
}

test "SOCKHASH lifecycle handles FIN in both orders and half-close response" {
    var client_first: Lifecycle = .{};
    const client_fin = client_first.observe(.client, .eof);
    try std.testing.expect(client_fin.shutdown_upstream_send);
    try std.testing.expect(!client_fin.shutdown_client_send);
    try std.testing.expect(!client_fin.close);
    const response_activity = client_first.observe(.upstream, .none);
    try std.testing.expect(!response_activity.close);
    try std.testing.expect(!response_activity.shutdown_upstream_send);
    const upstream_fin = client_first.observe(.upstream, .eof);
    try std.testing.expect(upstream_fin.shutdown_client_send);
    try std.testing.expect(upstream_fin.close);

    var upstream_first: Lifecycle = .{};
    const first = upstream_first.observe(.upstream, .eof);
    try std.testing.expect(first.shutdown_client_send);
    try std.testing.expect(!first.close);
    const second = upstream_first.observe(.client, .eof);
    try std.testing.expect(second.shutdown_upstream_send);
    try std.testing.expect(second.close);
}

test "SOCKHASH monitor ignores a source after observing its FIN" {
    const active = sourcePollFd(42, false);
    try std.testing.expectEqual(@as(fd_t, 42), active.fd);
    try std.testing.expect(active.events & posix.POLL.IN != 0);
    try std.testing.expect(active.events & poll_rdhup != 0);

    const half_closed = sourcePollFd(42, true);
    try std.testing.expectEqual(@as(fd_t, -1), half_closed.fd);
    try std.testing.expectEqual(@as(i16, 0), half_closed.events);
}

test "SOCKHASH admission propagates FIN observed by initial source kicks exactly once" {
    const client_first = lifecycleAfterKicks(.eof, .redirected);
    try std.testing.expect(client_first.state.client_eof);
    try std.testing.expect(!client_first.state.upstream_eof);
    try std.testing.expect(client_first.actions.shutdown_upstream_send);
    try std.testing.expect(!client_first.actions.shutdown_client_send);
    var client_state = client_first.state;
    try std.testing.expect(!client_state.observe(.client, .eof).shutdown_upstream_send);

    const upstream_first = lifecycleAfterKicks(.redirected, .eof);
    try std.testing.expect(upstream_first.state.upstream_eof);
    try std.testing.expect(upstream_first.actions.shutdown_client_send);
    try std.testing.expect(!upstream_first.actions.shutdown_upstream_send);
    var upstream_state = upstream_first.state;
    try std.testing.expect(!upstream_state.observe(.upstream, .eof).shutdown_client_send);

    const both = lifecycleAfterKicks(.eof, .eof);
    try std.testing.expect(both.actions.shutdown_client_send);
    try std.testing.expect(both.actions.shutdown_upstream_send);
    try std.testing.expect(both.actions.close);
}

test "SOCKHASH lifecycle propagates reset and does not repeat shutdown" {
    var lifecycle: Lifecycle = .{};
    const reset = lifecycle.observe(.client, .reset);
    try std.testing.expect(reset.close);
    try std.testing.expect(lifecycle.reset);

    var half_closed: Lifecycle = .{};
    const first = half_closed.observe(.client, .eof);
    const duplicate = half_closed.observe(.client, .eof);
    try std.testing.expect(first.shutdown_upstream_send);
    try std.testing.expect(!duplicate.shutdown_upstream_send);
}

test "SOCKHASH idle timeout uses monotonic saturating elapsed time" {
    try std.testing.expect(!idleExpired(100, 199, 100));
    try std.testing.expect(idleExpired(100, 200, 100));
    try std.testing.expect(!idleExpired(200, 100, 100));
}

test "SOCKHASH teardown ownership releases exactly once" {
    var ownership: CleanupOwnership = .{};
    try std.testing.expect(ownership.release());
    try std.testing.expect(!ownership.release());
}

test "bounded delivery preserves ordering under backpressure" {
    const Pipe = struct {
        pending: [64]u8 = undefined,
        pending_start: usize = 0,
        pending_end: usize = 0,
        delivered: [64]u8 = undefined,
        delivered_len: usize = 0,

        fn enqueue(self: *@This(), bytes: []const u8) void {
            @memcpy(self.pending[self.pending_end..][0..bytes.len], bytes);
            self.pending_end += bytes.len;
        }

        fn drain(self: *@This(), capacity: usize) void {
            const count = @min(capacity, self.pending_end - self.pending_start);
            @memcpy(
                self.delivered[self.delivered_len..][0..count],
                self.pending[self.pending_start..][0..count],
            );
            self.pending_start += count;
            self.delivered_len += count;
        }
    };

    var pipe: Pipe = .{};
    pipe.enqueue("prequeued-");
    pipe.drain(3);
    pipe.enqueue("post-cutover");
    pipe.drain(2);
    pipe.drain(64);
    try std.testing.expectEqualStrings(
        "prequeued-post-cutover",
        pipe.delivered[0..pipe.delivered_len],
    );
}
