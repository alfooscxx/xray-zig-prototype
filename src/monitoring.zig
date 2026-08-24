const std = @import("std");
const Io = std.Io;

const config = @import("config/mod.zig");

pub const max_tags = 16;
pub const max_tag_len = 63;
pub const event_capacity = 64;

const AtomicU64 = std.atomic.Value(u64);
const AtomicBool = std.atomic.Value(bool);

pub const ConnectionStage = enum { dispatch, outbound, raw_reactor, sockhash };
pub const DnsResult = enum { success, format_error, servfail, timeout };
pub const Qtype = enum { a, aaaa, other };
pub const Family = enum { ipv4, ipv6 };
pub const AllocationResult = enum { allocated, reused, exhausted, publish_error };
pub const LookupResult = enum { hit, miss };
pub const Owner = enum { freedom, vless_vision, generic };
pub const OffloadResult = enum { offloaded, raw_fallback, hybrid_raw, failed_closed };
pub const FallbackReason = enum {
    none,
    capacity,
    duplicate,
    socket_cookie,
    map_prepare,
    client_source,
    upstream_source,
    client_kick_payload,
    upstream_kick_payload,
    nonempty_preface,
};
pub const RealityStage = enum { tcp_connect, client_hello, server_response, vless_response_header, established };
pub const VisionPhase = enum { scanning, framed_transfer, raw_handoff, offloaded_transfer };
pub const VisionTransition = enum { command_direct, raw_handoff, sockhash_handoff };
pub const VisionGateResult = enum { command_direct, continue_until_eof, protocol_error };
pub const VisionPath = enum { framed, direct };
pub const EventKind = enum {
    runtime_started,
    runtime_ready,
    connection_rejected,
    dns_failure,
    fakedns_failure,
    reality_failure,
    sockhash_fallback,
    sockhash_closed,
};

const dns_duration_bounds_ns = [_]u64{
    1 * std.time.ns_per_ms,
    5 * std.time.ns_per_ms,
    10 * std.time.ns_per_ms,
    25 * std.time.ns_per_ms,
    50 * std.time.ns_per_ms,
    100 * std.time.ns_per_ms,
    250 * std.time.ns_per_ms,
    500 * std.time.ns_per_ms,
    1 * std.time.ns_per_s,
    2 * std.time.ns_per_s,
    5 * std.time.ns_per_s,
};

const reality_duration_bounds_ns = [_]u64{
    10 * std.time.ns_per_ms,
    25 * std.time.ns_per_ms,
    50 * std.time.ns_per_ms,
    100 * std.time.ns_per_ms,
    250 * std.time.ns_per_ms,
    500 * std.time.ns_per_ms,
    1 * std.time.ns_per_s,
    2 * std.time.ns_per_s,
    5 * std.time.ns_per_s,
    10 * std.time.ns_per_s,
    15 * std.time.ns_per_s,
};

fn atomicArray(comptime len: usize) [len]AtomicU64 {
    var values: [len]AtomicU64 = undefined;
    for (&values) |*value| value.* = .init(0);
    return values;
}
const Tag = struct {
    bytes: [max_tag_len]u8 = @splat(0),
    len: u8 = 0,

    fn set(self: *Tag, value: []const u8) void {
        const len = @min(value.len, self.bytes.len);
        for (value[0..len], 0..) |byte, index| {
            self.bytes[index] = switch (byte) {
                'a'...'z', 'A'...'Z', '0'...'9', '_', '-', '.', ':', '[', ']' => byte,
                else => '_',
            };
        }
        self.len = @intCast(len);
    }

    fn slice(self: *const Tag) []const u8 {
        return self.bytes[0..self.len];
    }
};

const Event = struct {
    sequence: u64 = 0,
    timestamp_ns: u64 = 0,
    kind: EventKind = .runtime_started,
    detail: FallbackReason = .none,
};

pub const Registry = struct {
    enabled: AtomicBool = .init(true),
    ready: AtomicBool = .init(false),
    control_up: AtomicBool = .init(false),
    start_ns: AtomicU64 = .init(0),
    expected_listeners: AtomicU64 = .init(0),
    active_listeners: AtomicU64 = .init(0),
    raw_limit: AtomicU64 = .init(0),
    raw_active: AtomicU64 = .init(0),
    raw_reactor_up: AtomicBool = .init(false),
    dns_active: AtomicU64 = .init(0),
    dns_limit: AtomicU64 = .init(16),
    reality_active: AtomicU64 = .init(0),
    reality_limit: AtomicU64 = .init(32),
    sockhash_capacity: AtomicU64 = .init(0),
    sockhash_monitor_up: AtomicBool = .init(false),
    bpf_sk_lookup_up: AtomicBool = .init(false),
    bpf_sockhash_parser_up: AtomicBool = .init(false),
    bpf_sockhash_verdict_up: AtomicBool = .init(false),
    fakedns_persistence_configured: AtomicBool = .init(false),
    fakedns_pin_compatible: AtomicBool = .init(false),
    bpf_fake_capacity: AtomicU64 = .init(0),
    bpf_lookup: [5]AtomicU64 = atomicArray(5),
    bpf_socket_assign: [4]AtomicU64 = atomicArray(4),
    bpf_map_updates: [4]AtomicU64 = atomicArray(4),
    fakedns_capacity: [2]AtomicU64 = atomicArray(2),
    fakedns_leases: [2]AtomicU64 = atomicArray(2),
    connections_active: [@typeInfo(ConnectionStage).@"enum".fields.len]AtomicU64 = atomicArray(@typeInfo(ConnectionStage).@"enum".fields.len),
    dns_total: [@typeInfo(Qtype).@"enum".fields.len * @typeInfo(DnsResult).@"enum".fields.len]AtomicU64 = atomicArray(@typeInfo(Qtype).@"enum".fields.len * @typeInfo(DnsResult).@"enum".fields.len),
    dns_duration: [dns_duration_bounds_ns.len + 1]AtomicU64 = atomicArray(dns_duration_bounds_ns.len + 1),
    fakedns_allocations: [2 * @typeInfo(AllocationResult).@"enum".fields.len]AtomicU64 = atomicArray(2 * @typeInfo(AllocationResult).@"enum".fields.len),
    fakedns_lookups: [2 * @typeInfo(LookupResult).@"enum".fields.len]AtomicU64 = atomicArray(2 * @typeInfo(LookupResult).@"enum".fields.len),
    reality_total: [@typeInfo(RealityStage).@"enum".fields.len * 2]AtomicU64 = atomicArray(@typeInfo(RealityStage).@"enum".fields.len * 2),
    reality_duration: [reality_duration_bounds_ns.len + 1]AtomicU64 = atomicArray(reality_duration_bounds_ns.len + 1),
    offload_total: [@typeInfo(Owner).@"enum".fields.len * @typeInfo(OffloadResult).@"enum".fields.len]AtomicU64 = atomicArray(@typeInfo(Owner).@"enum".fields.len * @typeInfo(OffloadResult).@"enum".fields.len),
    offload_fallback: [@typeInfo(Owner).@"enum".fields.len * @typeInfo(FallbackReason).@"enum".fields.len]AtomicU64 = atomicArray(@typeInfo(Owner).@"enum".fields.len * @typeInfo(FallbackReason).@"enum".fields.len),
    offloaded_flows: [@typeInfo(Owner).@"enum".fields.len]AtomicU64 = atomicArray(@typeInfo(Owner).@"enum".fields.len),
    sockhash_bytes: [@typeInfo(Owner).@"enum".fields.len * 2]AtomicU64 = atomicArray(@typeInfo(Owner).@"enum".fields.len * 2),
    sockhash_packets: AtomicU64 = .init(0),
    sockhash_kernel_bytes: AtomicU64 = .init(0),
    sockhash_redirect_errors: AtomicU64 = .init(0),
    sockhash_closed_bytes: AtomicU64 = .init(0),
    raw_bytes: [2]AtomicU64 = atomicArray(2),
    vision_bytes: [2 * @typeInfo(VisionPath).@"enum".fields.len]AtomicU64 = atomicArray(2 * @typeInfo(VisionPath).@"enum".fields.len),
    vision_active: [@typeInfo(VisionPhase).@"enum".fields.len]AtomicU64 = atomicArray(@typeInfo(VisionPhase).@"enum".fields.len),
    vision_transitions: [@typeInfo(VisionTransition).@"enum".fields.len * 2]AtomicU64 = atomicArray(@typeInfo(VisionTransition).@"enum".fields.len * 2),
    vision_gate: [2 * @typeInfo(VisionGateResult).@"enum".fields.len]AtomicU64 = atomicArray(2 * @typeInfo(VisionGateResult).@"enum".fields.len),
    connection_rejections: AtomicU64 = .init(0),
    connection_errors: AtomicU64 = .init(0),
    connection_successes: AtomicU64 = .init(0),
    routing_default: AtomicU64 = .init(0),
    routing_rule: AtomicU64 = .init(0),

    inbound_tags: [max_tags]Tag = [_]Tag{.{}} ** max_tags,
    outbound_tags: [max_tags]Tag = [_]Tag{.{}} ** max_tags,
    resolver_tags: [max_tags]Tag = [_]Tag{.{}} ** max_tags,
    inbound_count: usize = 0,
    outbound_count: usize = 0,
    resolver_count: usize = 0,
    connection_by_inbound: [max_tags * 2]AtomicU64 = atomicArray(max_tags * 2),
    connection_by_outbound: [max_tags * 2]AtomicU64 = atomicArray(max_tags * 2),
    routing_by_outbound: [max_tags * 2]AtomicU64 = atomicArray(max_tags * 2),
    dns_by_resolver: [max_tags * @typeInfo(DnsResult).@"enum".fields.len]AtomicU64 = atomicArray(max_tags * @typeInfo(DnsResult).@"enum".fields.len),

    event_mutex: std.atomic.Mutex = .unlocked,
    events: [event_capacity]Event = [_]Event{.{}} ** event_capacity,
    event_next: usize = 0,
    event_sequence: u64 = 0,

    pub fn reset(self: *Registry, cfg: *const config.Config, enabled: bool, start_ns: u64, raw_limit: usize) void {
        self.enabled.store(enabled, .release);
        self.ready.store(false, .release);
        self.control_up.store(false, .release);
        self.start_ns.store(start_ns, .release);
        self.expected_listeners.store(cfg.inbounds.len, .release);
        self.active_listeners.store(0, .release);
        self.raw_limit.store(raw_limit, .release);
        self.raw_active.store(0, .release);
        self.raw_reactor_up.store(false, .release);
        self.dns_active.store(0, .release);
        self.reality_active.store(0, .release);
        self.sockhash_capacity.store(0, .release);
        self.sockhash_monitor_up.store(false, .release);
        self.bpf_sk_lookup_up.store(false, .release);
        self.bpf_sockhash_parser_up.store(false, .release);
        self.bpf_sockhash_verdict_up.store(false, .release);
        self.fakedns_persistence_configured.store(false, .release);
        self.fakedns_pin_compatible.store(false, .release);
        self.bpf_fake_capacity.store(0, .release);
        zero(&self.bpf_lookup);
        zero(&self.bpf_socket_assign);
        zero(&self.bpf_map_updates);
        zero(&self.fakedns_capacity);
        zero(&self.fakedns_leases);
        zero(&self.connections_active);
        zero(&self.dns_total);
        zero(&self.dns_duration);
        zero(&self.fakedns_allocations);
        zero(&self.fakedns_lookups);
        zero(&self.reality_total);
        zero(&self.reality_duration);
        zero(&self.offload_total);
        zero(&self.offload_fallback);
        zero(&self.offloaded_flows);
        zero(&self.sockhash_bytes);
        zero(&self.raw_bytes);
        zero(&self.vision_bytes);
        zero(&self.vision_active);
        zero(&self.vision_transitions);
        zero(&self.vision_gate);
        zero(&self.connection_by_inbound);
        zero(&self.connection_by_outbound);
        zero(&self.routing_by_outbound);
        zero(&self.dns_by_resolver);
        self.sockhash_packets.store(0, .release);
        self.sockhash_kernel_bytes.store(0, .release);
        self.sockhash_redirect_errors.store(0, .release);
        self.sockhash_closed_bytes.store(0, .release);
        self.connection_errors.store(0, .release);
        self.connection_successes.store(0, .release);
        self.connection_rejections.store(0, .release);
        self.routing_default.store(0, .release);
        self.routing_rule.store(0, .release);

        self.inbound_count = 0;
        self.outbound_count = 0;
        self.resolver_count = 0;
        for (cfg.inbounds) |inbound| self.addTag(&self.inbound_tags, &self.inbound_count, inbound.tag orelse "-");
        for (cfg.outbounds) |outbound| self.addTag(&self.outbound_tags, &self.outbound_count, outbound.tag orelse outbound.protocol);
        if (cfg.dns) |dns_cfg| for (dns_cfg.servers) |server| self.addTag(&self.resolver_tags, &self.resolver_count, server.resolver);

        lock(&self.event_mutex);
        defer self.event_mutex.unlock();
        self.events = [_]Event{.{}} ** event_capacity;
        self.event_next = 0;
        self.event_sequence = 0;
        self.addEventLocked(.runtime_started, .none, start_ns);
    }

    fn zero(values: anytype) void {
        for (values) |*value| value.store(0, .release);
    }

    fn addTag(self: *Registry, tags: *[max_tags]Tag, count: *usize, value: []const u8) void {
        _ = self;
        for (tags[0..count.*]) |tag| if (std.mem.eql(u8, tag.slice(), value)) return;
        if (count.* == tags.len) return;
        tags[count.*].set(value);
        count.* += 1;
    }

    fn findTag(tags: []const Tag, value: ?[]const u8) ?usize {
        const actual = value orelse "-";
        for (tags, 0..) |tag, index| if (std.mem.eql(u8, tag.slice(), actual)) return index;
        return null;
    }

    pub fn setReady(self: *Registry, value: bool, now_ns: u64) void {
        self.ready.store(value, .release);
        if (value) self.addEvent(.runtime_ready, .none, now_ns);
    }

    pub fn listenerStarted(self: *Registry) void {
        _ = self.active_listeners.fetchAdd(1, .release);
    }

    pub fn listenerStopped(self: *Registry) void {
        _ = self.active_listeners.fetchSub(1, .release);
    }

    pub fn connectionStart(self: *Registry) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.connections_active[@intFromEnum(ConnectionStage.dispatch)].fetchAdd(1, .monotonic);
    }

    pub fn connectionMoveToOutbound(self: *Registry) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.connections_active[@intFromEnum(ConnectionStage.dispatch)].fetchSub(1, .monotonic);
        _ = self.connections_active[@intFromEnum(ConnectionStage.outbound)].fetchAdd(1, .monotonic);
    }

    pub fn connectionEnd(self: *Registry, inbound: ?[]const u8, outbound: ?[]const u8, success: bool, stage: ConnectionStage) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.connections_active[@intFromEnum(stage)].fetchSub(1, .monotonic);
        const result_index: usize = if (success) 0 else 1;
        if (success) _ = self.connection_successes.fetchAdd(1, .monotonic) else _ = self.connection_errors.fetchAdd(1, .monotonic);
        if (findTag(self.inbound_tags[0..self.inbound_count], inbound)) |index|
            _ = self.connection_by_inbound[index * 2 + result_index].fetchAdd(1, .monotonic);
        if (findTag(self.outbound_tags[0..self.outbound_count], outbound)) |index|
            _ = self.connection_by_outbound[index * 2 + result_index].fetchAdd(1, .monotonic);
    }

    pub fn connectionRejected(self: *Registry, now_ns: u64) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.connection_errors.fetchAdd(1, .monotonic);
        _ = self.connection_rejections.fetchAdd(1, .monotonic);
        self.addEvent(.connection_rejected, .capacity, now_ns);
    }

    pub fn addRawBytes(self: *Registry, direction: enum { uplink, downlink }, count: usize) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.raw_bytes[@intFromEnum(direction)].fetchAdd(count, .monotonic);
    }

    pub fn setRawActive(self: *Registry, count: usize) void {
        self.raw_active.store(count, .release);
        self.connections_active[@intFromEnum(ConnectionStage.raw_reactor)].store(
            if (self.enabled.load(.monotonic)) count else 0,
            .release,
        );
    }

    pub fn addVisionBytes(self: *Registry, direction: enum { uplink, downlink }, path: VisionPath, count: usize) void {
        if (!self.enabled.load(.monotonic)) return;
        const paths = @typeInfo(VisionPath).@"enum".fields.len;
        const index = @as(usize, @intFromEnum(direction)) * paths + @intFromEnum(path);
        _ = self.vision_bytes[index].fetchAdd(count, .monotonic);
    }

    pub fn visionPhaseStart(self: *Registry, phase: VisionPhase) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.vision_active[@intFromEnum(phase)].fetchAdd(1, .monotonic);
    }

    pub fn visionPhaseEnd(self: *Registry, phase: VisionPhase) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.vision_active[@intFromEnum(phase)].fetchSub(1, .monotonic);
    }

    pub fn visionTransition(self: *Registry, transition: VisionTransition, success: bool) void {
        if (!self.enabled.load(.monotonic)) return;
        const index = @as(usize, @intFromEnum(transition)) * 2 + @intFromBool(!success);
        _ = self.vision_transitions[index].fetchAdd(1, .monotonic);
    }

    pub fn visionGate(self: *Registry, direction: enum { uplink, downlink }, result: VisionGateResult) void {
        if (!self.enabled.load(.monotonic)) return;
        const results = @typeInfo(VisionGateResult).@"enum".fields.len;
        const index = @as(usize, @intFromEnum(direction)) * results + @intFromEnum(result);
        _ = self.vision_gate[index].fetchAdd(1, .monotonic);
    }

    pub fn routingDecision(self: *Registry, outbound: ?[]const u8, matched_rule: bool) void {
        if (!self.enabled.load(.monotonic)) return;
        if (matched_rule) _ = self.routing_rule.fetchAdd(1, .monotonic) else _ = self.routing_default.fetchAdd(1, .monotonic);
        if (findTag(self.outbound_tags[0..self.outbound_count], outbound)) |index|
            _ = self.routing_by_outbound[index * 2 + @intFromBool(matched_rule)].fetchAdd(1, .monotonic);
    }

    pub fn dnsStart(self: *Registry) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.dns_active.fetchAdd(1, .monotonic);
    }

    pub fn dnsEnd(self: *Registry, qtype: Qtype, resolver: ?[]const u8, result: DnsResult, duration_ns: u64) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.dns_active.fetchSub(1, .monotonic);
        const result_count = @typeInfo(DnsResult).@"enum".fields.len;
        const result_index = @as(usize, @intFromEnum(qtype)) * result_count + @intFromEnum(result);
        _ = self.dns_total[result_index].fetchAdd(1, .monotonic);
        if (resolver) |name| {
            if (findTag(self.resolver_tags[0..self.resolver_count], name)) |index| {
                _ = self.dns_by_resolver[index * result_count + @intFromEnum(result)].fetchAdd(1, .monotonic);
            }
        }
        observeHistogram(&self.dns_duration, &dns_duration_bounds_ns, duration_ns);
    }

    pub fn fakeDnsAllocation(self: *Registry, family: Family, result: AllocationResult) void {
        if (!self.enabled.load(.monotonic)) return;
        const count = @typeInfo(AllocationResult).@"enum".fields.len;
        const index = @as(usize, @intFromEnum(family)) * count + @intFromEnum(result);
        _ = self.fakedns_allocations[index].fetchAdd(1, .monotonic);
    }

    pub fn fakeDnsLookup(self: *Registry, family: Family, result: LookupResult) void {
        if (!self.enabled.load(.monotonic)) return;
        const count = @typeInfo(LookupResult).@"enum".fields.len;
        const index = @as(usize, @intFromEnum(family)) * count + @intFromEnum(result);
        _ = self.fakedns_lookups[index].fetchAdd(1, .monotonic);
    }

    pub fn bpfMapUpdate(self: *Registry, family: Family, success: bool) void {
        if (!self.enabled.load(.monotonic)) return;
        const index = @as(usize, @intFromEnum(family)) * 2 + @intFromBool(!success);
        _ = self.bpf_map_updates[index].fetchAdd(1, .monotonic);
    }

    pub fn realityStart(self: *Registry) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.reality_active.fetchAdd(1, .monotonic);
    }

    pub fn realityEnd(self: *Registry, stage: RealityStage, success: bool, duration_ns: u64) void {
        if (!self.enabled.load(.monotonic)) return;
        _ = self.reality_active.fetchSub(1, .monotonic);
        const index = @as(usize, @intFromEnum(stage)) * 2 + @intFromBool(!success);
        _ = self.reality_total[index].fetchAdd(1, .monotonic);
        observeHistogram(&self.reality_duration, &reality_duration_bounds_ns, duration_ns);
    }

    pub fn realityOutcome(self: *Registry, stage: RealityStage, success: bool) void {
        if (!self.enabled.load(.monotonic)) return;
        const index = @as(usize, @intFromEnum(stage)) * 2 + @intFromBool(!success);
        _ = self.reality_total[index].fetchAdd(1, .monotonic);
    }

    pub fn offload(self: *Registry, owner: Owner, result: OffloadResult, reason: FallbackReason, now_ns: u64) void {
        if (result == .offloaded) {
            _ = self.offloaded_flows[@intFromEnum(owner)].fetchAdd(1, .monotonic);
            _ = self.connections_active[@intFromEnum(ConnectionStage.sockhash)].fetchAdd(1, .monotonic);
        }
        if (!self.enabled.load(.monotonic)) return;
        const results = @typeInfo(OffloadResult).@"enum".fields.len;
        const owner_index = @as(usize, @intFromEnum(owner));
        _ = self.offload_total[owner_index * results + @intFromEnum(result)].fetchAdd(1, .monotonic);
        if (result == .offloaded) return;
        const reasons = @typeInfo(FallbackReason).@"enum".fields.len;
        _ = self.offload_fallback[owner_index * reasons + @intFromEnum(reason)].fetchAdd(1, .monotonic);
        self.addEvent(.sockhash_fallback, reason, now_ns);
    }

    pub fn offloadClosed(self: *Registry, owner: Owner, uplink: u64, downlink: u64, redirect_errors: u64, now_ns: u64) void {
        const owner_index = @as(usize, @intFromEnum(owner));
        _ = self.offloaded_flows[owner_index].fetchSub(1, .monotonic);
        _ = self.connections_active[@intFromEnum(ConnectionStage.sockhash)].fetchSub(1, .monotonic);
        if (!self.enabled.load(.monotonic)) return;
        _ = self.sockhash_bytes[owner_index * 2].fetchAdd(uplink, .monotonic);
        _ = self.sockhash_bytes[owner_index * 2 + 1].fetchAdd(downlink, .monotonic);
        _ = self.sockhash_closed_bytes.fetchAdd(uplink +| downlink, .monotonic);
        _ = self.sockhash_redirect_errors.fetchAdd(redirect_errors, .monotonic);
        self.addEvent(.sockhash_closed, .none, now_ns);
    }

    pub fn updateSkLookupCounters(
        self: *Registry,
        hit: u64,
        miss: u64,
        pool_miss: u64,
        assign4_success: u64,
        assign4_error: u64,
        assign6_success: u64,
        assign6_error: u64,
        pass: u64,
        drop: u64,
    ) void {
        self.bpf_lookup[0].store(hit, .release);
        self.bpf_lookup[1].store(miss, .release);
        self.bpf_lookup[2].store(pool_miss, .release);
        self.bpf_lookup[3].store(pass, .release);
        self.bpf_lookup[4].store(drop, .release);
        self.bpf_socket_assign[0].store(assign4_success, .release);
        self.bpf_socket_assign[1].store(assign4_error, .release);
        self.bpf_socket_assign[2].store(assign6_success, .release);
        self.bpf_socket_assign[3].store(assign6_error, .release);
    }

    pub fn addEvent(self: *Registry, kind: EventKind, detail: FallbackReason, timestamp_ns: u64) void {
        if (!self.enabled.load(.monotonic)) return;
        lock(&self.event_mutex);
        defer self.event_mutex.unlock();
        self.addEventLocked(kind, detail, timestamp_ns);
    }

    fn addEventLocked(self: *Registry, kind: EventKind, detail: FallbackReason, timestamp_ns: u64) void {
        self.event_sequence +%= 1;
        self.events[self.event_next] = .{
            .sequence = self.event_sequence,
            .timestamp_ns = timestamp_ns,
            .kind = kind,
            .detail = detail,
        };
        self.event_next = (self.event_next + 1) % self.events.len;
    }

    pub fn renderStatus(self: *Registry, writer: *Io.Writer, now_ns: u64, dataplane: []const u8, version: []const u8) !void {
        const ready = self.isReady();
        try writer.print(
            "{{\"version\":\"{s}\",\"dataplane\":\"{s}\",\"ready\":{},\"uptime_seconds\":{d},\"listeners\":{{\"active\":{d},\"expected\":{d}}},\"capacity\":{{\"raw_reactor_up\":{},\"raw_active\":{d},\"raw_limit\":{d},\"dns_active\":{d},\"dns_limit\":{d}}}}}\n",
            .{
                version,
                dataplane,
                ready,
                uptimeSeconds(self, now_ns),
                self.active_listeners.load(.acquire),
                self.expected_listeners.load(.acquire),
                self.raw_reactor_up.load(.acquire),
                self.raw_active.load(.acquire),
                self.raw_limit.load(.acquire),
                self.dns_active.load(.acquire),
                self.dns_limit.load(.acquire),
            },
        );
    }

    pub fn renderBpfStatus(self: *Registry, writer: *Io.Writer) !void {
        try writer.print(
            "{{\"sk_lookup\":{},\"sockhash_parser\":{},\"sockhash_verdict\":{},\"sockhash_monitor\":{},\"fakedns_persistence_configured\":{},\"fakedns_pin_compatible\":{},\"offloaded_flows\":{d},\"flow_capacity\":{d},\"closed_bytes\":{d},\"kernel_bytes\":{d},\"byte_divergence\":{d}}}\n",
            .{
                self.bpf_sk_lookup_up.load(.acquire),
                self.bpf_sockhash_parser_up.load(.acquire),
                self.bpf_sockhash_verdict_up.load(.acquire),
                self.sockhash_monitor_up.load(.acquire),
                self.fakedns_persistence_configured.load(.acquire),
                self.fakedns_pin_compatible.load(.acquire),
                sumAtomic(&self.offloaded_flows),
                self.sockhash_capacity.load(.acquire),
                self.sockhash_closed_bytes.load(.acquire),
                self.sockhash_kernel_bytes.load(.acquire),
                divergence(
                    self.sockhash_closed_bytes.load(.acquire),
                    self.sockhash_kernel_bytes.load(.acquire),
                ),
            },
        );
    }

    pub fn renderEvents(self: *Registry, writer: *Io.Writer, requested_limit: usize) !void {
        const limit = @min(requested_limit, event_capacity);
        lock(&self.event_mutex);
        defer self.event_mutex.unlock();
        const available: usize = @min(@as(usize, @intCast(self.event_sequence)), event_capacity);
        const count = @min(limit, available);
        try writer.writeAll("{\"events\":[");
        var emitted: usize = 0;
        while (emitted < count) : (emitted += 1) {
            const distance = count - emitted;
            const index = (self.event_next + event_capacity - distance) % event_capacity;
            const event = self.events[index];
            if (emitted != 0) try writer.writeByte(',');
            try writer.print("{{\"sequence\":{d},\"timestamp_ns\":{d},\"kind\":\"{s}\",\"detail\":\"{s}\"}}", .{
                event.sequence,
                event.timestamp_ns,
                @tagName(event.kind),
                @tagName(event.detail),
            });
        }
        try writer.writeAll("]}\n");
    }

    pub fn renderMetrics(self: *Registry, writer: *Io.Writer, now_ns: u64, dataplane: []const u8, version: []const u8) !void {
        try writer.print("xray_zig_build_info{{version=\"{s}\",dataplane=\"{s}\"}} 1\n", .{ version, dataplane });
        try metric(writer, "xray_zig_ready", @intFromBool(self.isReady()));
        try metric(writer, "xray_zig_uptime_seconds", uptimeSeconds(self, now_ns));
        inline for (@typeInfo(ConnectionStage).@"enum".fields) |field| {
            const stage: ConnectionStage = @enumFromInt(field.value);
            try writer.print("xray_zig_connections_active{{network=\"tcp\",stage=\"{s}\"}} {d}\n", .{ field.name, self.connections_active[@intFromEnum(stage)].load(.acquire) });
        }
        try metric(writer, "xray_zig_connections_total{network=\"tcp\",inbound=\"all\",outbound=\"all\",result=\"success\"}", self.connection_successes.load(.acquire));
        try metric(writer, "xray_zig_connections_total{network=\"tcp\",inbound=\"all\",outbound=\"all\",result=\"error\"}", self.connection_errors.load(.acquire));
        try metric(writer, "xray_zig_connection_rejections_total{reason=\"capacity\"}", self.connection_rejections.load(.acquire));
        try metric(writer, "xray_zig_bytes_total{network=\"tcp\",direction=\"uplink\",path=\"raw_reactor\"}", self.raw_bytes[0].load(.acquire));
        try metric(writer, "xray_zig_bytes_total{network=\"tcp\",direction=\"downlink\",path=\"raw_reactor\"}", self.raw_bytes[1].load(.acquire));
        try metric(writer, "xray_zig_bytes_total{network=\"tcp\",direction=\"uplink\",path=\"vision_framed\"}", self.vision_bytes[0].load(.acquire));
        try metric(writer, "xray_zig_bytes_total{network=\"tcp\",direction=\"downlink\",path=\"vision_framed\"}", self.vision_bytes[2].load(.acquire));
        for (self.inbound_tags[0..self.inbound_count], 0..) |tag, index| {
            try writer.print("xray_zig_connections_total{{network=\"tcp\",inbound=\"{s}\",outbound=\"all\",result=\"success\"}} {d}\n", .{ tag.slice(), self.connection_by_inbound[index * 2].load(.acquire) });
            try writer.print("xray_zig_connections_total{{network=\"tcp\",inbound=\"{s}\",outbound=\"all\",result=\"error\"}} {d}\n", .{ tag.slice(), self.connection_by_inbound[index * 2 + 1].load(.acquire) });
        }
        for (self.outbound_tags[0..self.outbound_count], 0..) |tag, index| {
            try writer.print("xray_zig_connections_total{{network=\"tcp\",inbound=\"all\",outbound=\"{s}\",result=\"success\"}} {d}\n", .{ tag.slice(), self.connection_by_outbound[index * 2].load(.acquire) });
            try writer.print("xray_zig_connections_total{{network=\"tcp\",inbound=\"all\",outbound=\"{s}\",result=\"error\"}} {d}\n", .{ tag.slice(), self.connection_by_outbound[index * 2 + 1].load(.acquire) });
            try writer.print("xray_zig_routing_decisions_total{{outbound=\"{s}\",rule=\"default\",result=\"selected\"}} {d}\n", .{ tag.slice(), self.routing_by_outbound[index * 2].load(.acquire) });
            try writer.print("xray_zig_routing_decisions_total{{outbound=\"{s}\",rule=\"matched\",result=\"selected\"}} {d}\n", .{ tag.slice(), self.routing_by_outbound[index * 2 + 1].load(.acquire) });
        }
        try metric(writer, "xray_zig_dns_queries_active", self.dns_active.load(.acquire));
        try metric(writer, "xray_zig_dns_query_limit", self.dns_limit.load(.acquire));
        inline for (@typeInfo(Qtype).@"enum".fields) |qfield| inline for (@typeInfo(DnsResult).@"enum".fields) |rfield| {
            const index = qfield.value * @typeInfo(DnsResult).@"enum".fields.len + rfield.value;
            try writer.print("xray_zig_dns_queries_total{{qtype=\"{s}\",resolver=\"all\",result=\"{s}\"}} {d}\n", .{ qfield.name, rfield.name, self.dns_total[index].load(.acquire) });
        };
        for (self.resolver_tags[0..self.resolver_count], 0..) |tag, resolver_index| {
            inline for (@typeInfo(DnsResult).@"enum".fields) |rfield| {
                const index = resolver_index * @typeInfo(DnsResult).@"enum".fields.len + rfield.value;
                try writer.print("xray_zig_dns_queries_total{{qtype=\"all\",resolver=\"{s}\",result=\"{s}\"}} {d}\n", .{ tag.slice(), rfield.name, self.dns_by_resolver[index].load(.acquire) });
            }
        }
        try renderHistogram(writer, "xray_zig_dns_duration_seconds", &self.dns_duration, &dns_duration_bounds_ns, "resolver=\"all\"");
        inline for (@typeInfo(Family).@"enum".fields) |ffield| {
            const family: Family = @enumFromInt(ffield.value);
            try writer.print("xray_zig_fakedns_leases{{family=\"{s}\",state=\"active\"}} {d}\n", .{ ffield.name, self.fakedns_leases[@intFromEnum(family)].load(.acquire) });
            try writer.print("xray_zig_fakedns_pool_capacity{{family=\"{s}\"}} {d}\n", .{ ffield.name, self.fakedns_capacity[@intFromEnum(family)].load(.acquire) });
            inline for (@typeInfo(AllocationResult).@"enum".fields) |rfield| {
                const index = ffield.value * @typeInfo(AllocationResult).@"enum".fields.len + rfield.value;
                try writer.print("xray_zig_fakedns_allocations_total{{family=\"{s}\",result=\"{s}\"}} {d}\n", .{ ffield.name, rfield.name, self.fakedns_allocations[index].load(.acquire) });
            }
            inline for (@typeInfo(LookupResult).@"enum".fields) |rfield| {
                const index = ffield.value * @typeInfo(LookupResult).@"enum".fields.len + rfield.value;
                try writer.print("xray_zig_fakedns_lookup_total{{family=\"{s}\",result=\"{s}\"}} {d}\n", .{ ffield.name, rfield.name, self.fakedns_lookups[index].load(.acquire) });
            }
        }
        try metric(writer, "xray_zig_reality_handshakes_active", self.reality_active.load(.acquire));
        inline for (@typeInfo(RealityStage).@"enum".fields) |field| {
            try writer.print("xray_zig_reality_handshakes_total{{stage=\"{s}\",result=\"success\"}} {d}\n", .{ field.name, self.reality_total[field.value * 2].load(.acquire) });
            try writer.print("xray_zig_reality_handshakes_total{{stage=\"{s}\",result=\"error\"}} {d}\n", .{ field.name, self.reality_total[field.value * 2 + 1].load(.acquire) });
        }
        try renderHistogram(writer, "xray_zig_reality_handshake_duration_seconds", &self.reality_duration, &reality_duration_bounds_ns, "");
        inline for (@typeInfo(VisionPhase).@"enum".fields) |field| {
            try writer.print("xray_zig_vision_connections_active{{phase=\"{s}\"}} {d}\n", .{ field.name, self.vision_active[field.value].load(.acquire) });
        }
        inline for (@typeInfo(VisionTransition).@"enum".fields) |field| {
            try writer.print("xray_zig_vision_transitions_total{{transition=\"{s}\",result=\"success\"}} {d}\n", .{ field.name, self.vision_transitions[field.value * 2].load(.acquire) });
            try writer.print("xray_zig_vision_transitions_total{{transition=\"{s}\",result=\"error\"}} {d}\n", .{ field.name, self.vision_transitions[field.value * 2 + 1].load(.acquire) });
        }
        inline for (.{ "uplink", "downlink" }, 0..) |direction, direction_index| inline for (@typeInfo(VisionGateResult).@"enum".fields) |field| {
            const index = direction_index * @typeInfo(VisionGateResult).@"enum".fields.len + field.value;
            try writer.print("xray_zig_vision_gate_total{{direction=\"{s}\",result=\"{s}\"}} {d}\n", .{ direction, field.name, self.vision_gate[index].load(.acquire) });
        };
        inline for (.{ "uplink", "downlink" }, 0..) |direction, direction_index| inline for (@typeInfo(VisionPath).@"enum".fields) |field| {
            const index = direction_index * @typeInfo(VisionPath).@"enum".fields.len + field.value;
            try writer.print("xray_zig_vision_bytes_total{{direction=\"{s}\",path=\"{s}\"}} {d}\n", .{ direction, field.name, self.vision_bytes[index].load(.acquire) });
        };
        try metric(writer, "xray_zig_raw_reactor_connections", self.raw_active.load(.acquire));
        try metric(writer, "xray_zig_raw_reactor_limit", self.raw_limit.load(.acquire));
        try writer.print("xray_zig_bpf_program_up{{hook=\"sk_lookup\"}} {d}\n", .{@intFromBool(self.bpf_sk_lookup_up.load(.acquire))});
        try writer.print("xray_zig_bpf_program_up{{hook=\"sockhash_parser\"}} {d}\n", .{@intFromBool(self.bpf_sockhash_parser_up.load(.acquire))});
        try writer.print("xray_zig_bpf_program_up{{hook=\"sockhash_verdict\"}} {d}\n", .{@intFromBool(self.bpf_sockhash_verdict_up.load(.acquire))});
        inline for (@typeInfo(Owner).@"enum".fields) |ofield| {
            const owner: Owner = @enumFromInt(ofield.value);
            try writer.print("xray_zig_bpf_offloaded_flows{{network=\"tcp\",owner=\"{s}\"}} {d}\n", .{ ofield.name, self.offloaded_flows[@intFromEnum(owner)].load(.acquire) });
            inline for (@typeInfo(OffloadResult).@"enum".fields) |rfield| {
                const index = ofield.value * @typeInfo(OffloadResult).@"enum".fields.len + rfield.value;
                try writer.print("xray_zig_bpf_offload_total{{network=\"tcp\",owner=\"{s}\",result=\"{s}\"}} {d}\n", .{ ofield.name, rfield.name, self.offload_total[index].load(.acquire) });
            }
            inline for (@typeInfo(FallbackReason).@"enum".fields) |rfield| {
                if (rfield.value != @intFromEnum(FallbackReason.none)) {
                    const index = ofield.value * @typeInfo(FallbackReason).@"enum".fields.len + rfield.value;
                    try writer.print("xray_zig_bpf_offload_fallback_total{{network=\"tcp\",owner=\"{s}\",reason=\"{s}\"}} {d}\n", .{ ofield.name, rfield.name, self.offload_fallback[index].load(.acquire) });
                }
            }
            try writer.print("xray_zig_bpf_sockhash_bytes_total{{network=\"tcp\",owner=\"{s}\",direction=\"uplink\"}} {d}\n", .{ ofield.name, self.sockhash_bytes[ofield.value * 2].load(.acquire) });
            try writer.print("xray_zig_bpf_sockhash_bytes_total{{network=\"tcp\",owner=\"{s}\",direction=\"downlink\"}} {d}\n", .{ ofield.name, self.sockhash_bytes[ofield.value * 2 + 1].load(.acquire) });
        }
        try metric(writer, "xray_zig_bpf_sockhash_packets_total{network=\"tcp\"}", self.sockhash_packets.load(.acquire));
        try metric(writer, "xray_zig_bpf_sockhash_redirect_errors_total{network=\"tcp\"}", self.sockhash_redirect_errors.load(.acquire));
        try metric(writer, "xray_zig_bpf_lookup_total{hook=\"sk_lookup\",result=\"hit\"}", self.bpf_lookup[0].load(.acquire));
        try metric(writer, "xray_zig_bpf_lookup_total{hook=\"sk_lookup\",result=\"miss\"}", self.bpf_lookup[1].load(.acquire));
        try metric(writer, "xray_zig_bpf_lookup_total{hook=\"sk_lookup\",result=\"pool_miss\"}", self.bpf_lookup[2].load(.acquire));
        try metric(writer, "xray_zig_bpf_lookup_total{hook=\"sk_lookup\",result=\"pass\"}", self.bpf_lookup[3].load(.acquire));
        try metric(writer, "xray_zig_bpf_lookup_total{hook=\"sk_lookup\",result=\"drop\"}", self.bpf_lookup[4].load(.acquire));
        try metric(writer, "xray_zig_bpf_socket_assign_total{family=\"ipv4\",result=\"success\"}", self.bpf_socket_assign[0].load(.acquire));
        try metric(writer, "xray_zig_bpf_socket_assign_total{family=\"ipv4\",result=\"error\"}", self.bpf_socket_assign[1].load(.acquire));
        try metric(writer, "xray_zig_bpf_socket_assign_total{family=\"ipv6\",result=\"success\"}", self.bpf_socket_assign[2].load(.acquire));
        try metric(writer, "xray_zig_bpf_socket_assign_total{family=\"ipv6\",result=\"error\"}", self.bpf_socket_assign[3].load(.acquire));
        try metric(writer, "xray_zig_bpf_packets_total{hook=\"sockhash\",action=\"redirect\"}", self.sockhash_packets.load(.acquire));
        try metric(writer, "xray_zig_bpf_bytes_total{hook=\"sockhash\",action=\"redirect\"}", self.sockhash_kernel_bytes.load(.acquire));
        try metric(writer, "xray_zig_bpf_events_dropped_total", 0);
        try metric(writer, "xray_zig_bpf_map_capacity{map=\"sockhash_flows\"}", self.sockhash_capacity.load(.acquire));
        try metric(writer, "xray_zig_bpf_map_entries{map=\"sockhash_flows\"}", sumAtomic(&self.offloaded_flows));
        try metric(writer, "xray_zig_bpf_map_capacity{map=\"fake4\"}", self.bpf_fake_capacity.load(.acquire));
        try metric(writer, "xray_zig_bpf_map_capacity{map=\"fake6\"}", self.bpf_fake_capacity.load(.acquire));
        try metric(writer, "xray_zig_bpf_map_entries{map=\"fake4\"}", self.fakedns_leases[0].load(.acquire));
        try metric(writer, "xray_zig_bpf_map_entries{map=\"fake6\"}", self.fakedns_leases[1].load(.acquire));
        try metric(writer, "xray_zig_bpf_map_update_total{map=\"fake4\",result=\"success\"}", self.bpf_map_updates[0].load(.acquire));
        try metric(writer, "xray_zig_bpf_map_update_total{map=\"fake4\",result=\"error\"}", self.bpf_map_updates[1].load(.acquire));
        try metric(writer, "xray_zig_bpf_map_update_total{map=\"fake6\",result=\"success\"}", self.bpf_map_updates[2].load(.acquire));
        try metric(writer, "xray_zig_bpf_map_update_total{map=\"fake6\",result=\"error\"}", self.bpf_map_updates[3].load(.acquire));
        const sk_counter_entries: u64 = if (self.bpf_sk_lookup_up.load(.acquire)) 9 else 0;
        try metric(writer, "xray_zig_bpf_map_capacity{map=\"sk_lookup_counters\"}", sk_counter_entries);
        try metric(writer, "xray_zig_bpf_map_entries{map=\"sk_lookup_counters\"}", sk_counter_entries);
    }

    fn isReady(self: *Registry) bool {
        return self.ready.load(.acquire) and
            self.control_up.load(.acquire) and
            self.raw_reactor_up.load(.acquire) and
            self.active_listeners.load(.acquire) == self.expected_listeners.load(.acquire) and
            self.raw_limit.load(.acquire) != 0 and
            (!self.fakedns_persistence_configured.load(.acquire) or self.fakedns_pin_compatible.load(.acquire)) and
            (!self.bpf_sk_lookup_up.load(.acquire) or self.sockhash_capacity.load(.acquire) == 0 or self.sockhash_monitor_up.load(.acquire));
    }
};

pub var registry: Registry = .{};

fn observeHistogram(values: anytype, bounds: []const u64, sample: u64) void {
    var index: usize = 0;
    while (index < bounds.len and sample > bounds[index]) : (index += 1) {}
    _ = values[index].fetchAdd(1, .monotonic);
}

fn renderHistogram(writer: *Io.Writer, name: []const u8, values: anytype, bounds: []const u64, labels: []const u8) !void {
    var cumulative: u64 = 0;
    for (bounds, 0..) |bound, index| {
        cumulative +%= values[index].load(.acquire);
        if (labels.len == 0)
            try writer.print("{s}_bucket{{le=\"{d}.{d:0>3}\"}} {d}\n", .{ name, bound / std.time.ns_per_s, (bound % std.time.ns_per_s) / std.time.ns_per_ms, cumulative })
        else
            try writer.print("{s}_bucket{{{s},le=\"{d}.{d:0>3}\"}} {d}\n", .{ name, labels, bound / std.time.ns_per_s, (bound % std.time.ns_per_s) / std.time.ns_per_ms, cumulative });
    }
    cumulative +%= values[bounds.len].load(.acquire);
    if (labels.len == 0)
        try writer.print("{s}_bucket{{le=\"+Inf\"}} {d}\n", .{ name, cumulative })
    else
        try writer.print("{s}_bucket{{{s},le=\"+Inf\"}} {d}\n", .{ name, labels, cumulative });
}

fn metric(writer: *Io.Writer, name: []const u8, value: anytype) !void {
    try writer.print("{s} {d}\n", .{ name, value });
}

fn uptimeSeconds(self: *Registry, now_ns: u64) u64 {
    return (now_ns -| self.start_ns.load(.acquire)) / std.time.ns_per_s;
}

fn sumAtomic(values: anytype) u64 {
    var result: u64 = 0;
    for (values) |*value| result +%= value.load(.acquire);
    return result;
}

fn divergence(first: u64, second: u64) u64 {
    return if (first >= second) first - second else second - first;
}

fn lock(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

test "registry snapshot has bounded stable labels" {
    const source =
        \\{"inbounds":[{"tag":"in","port":1080,"protocol":"socks"}],
        \\ "outbounds":[{"tag":"direct","protocol":"freedom"}],
        \\ "routing":{"defaultOutboundTag":"direct"}}
    ;
    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();
    var value: Registry = .{};
    value.reset(&cfg, true, 100, 10);
    value.control_up.store(true, .release);
    value.raw_reactor_up.store(true, .release);
    value.active_listeners.store(1, .release);
    value.setReady(true, 101);
    value.connectionStart();
    value.connectionEnd("in", "direct", true, .dispatch);

    var buffer: [16 * 1024]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try value.renderMetrics(&writer, 2 * std.time.ns_per_s, "redirect", "test");
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "xray_zig_ready 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, writer.buffered(), "outbound=\"direct\"") != null);
}
