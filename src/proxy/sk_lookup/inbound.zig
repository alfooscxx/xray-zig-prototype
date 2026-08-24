const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const fakedns = @import("../../dns/fakedns.zig");
const log = @import("../../log.zig");
const monitoring = @import("../../monitoring.zig");
const session = @import("../../net/session.zig");
const bpf = @import("bpf.zig");
const sockhash = @import("sockhash.zig");

const linux = std.os.linux;

pub const Inbound = struct {
    inbound_tag: ?[]const u8,
    listener4: net.Server,
    listener6: net.Server,
    dataplane: bpf.Dataplane,
    sockhash_manager: ?sockhash.Manager,
    literal_excluded_ips: ?[]const config.IpRule,
    literal_proxy_server_ips: ?[]const config.IpRule,

    pub fn init(
        inbound: config.Inbound,
        fake_dns_cfg: config.FakeDnsConfig,
        allocator: std.mem.Allocator,
        io: Io,
    ) !Inbound {
        if (builtin.os.tag != .linux) return error.SkLookupRequiresLinux;
        const settings = inbound.sk_lookup orelse return error.MissingSkLookupSettings;
        const transparent_ifindex: ?u32 = if (settings.transparent_intercept) |transparent| blk: {
            const name = net.Interface.Name.fromSlice(transparent.ingress_interface) catch
                return error.InvalidTransparentIngressInterface;
            const interface = name.resolve(io) catch return error.TransparentIngressInterfaceNotFound;
            break :blk interface.index;
        } else null;

        var address4 = net.IpAddress.parse(settings.listen4, settings.port4) catch return error.InvalidSkLookupListen4;
        var listener4 = try address4.listen(io, .{ .reuse_address = true });
        errdefer listener4.deinit(io);
        try enableTransparentListener(listener4.socket.handle, .ip4);

        var address6 = net.IpAddress.parse(settings.listen6, settings.port6) catch return error.InvalidSkLookupListen6;
        var listener6 = try address6.listen(io, .{ .reuse_address = true });
        errdefer listener6.deinit(io);
        try enableTransparentListener(listener6.socket.handle, .ip6);

        const dataplane = try bpf.Dataplane.init(
            settings.max_map_entries,
            listener4.socket.handle,
            listener6.socket.handle,
            fake_dns_cfg,
            settings.fake_dns_persistence,
            settings.transparent_intercept,
            transparent_ifindex,
            io,
        );
        errdefer {
            var owned = dataplane;
            owned.deinit();
        }

        const sockhash_manager = if (settings.sockhash_offload) |offload|
            try sockhash.Manager.init(allocator, io, offload.max_flows, offload.idle_timeout_seconds)
        else
            null;

        return .{
            .inbound_tag = inbound.tag,
            .listener4 = listener4,
            .listener6 = listener6,
            .dataplane = dataplane,
            .sockhash_manager = sockhash_manager,
            .literal_excluded_ips = if (settings.transparent_intercept) |value| value.excluded_ips else null,
            .literal_proxy_server_ips = if (settings.transparent_intercept) |value| value.proxy_server_ips else null,
        };
    }

    pub fn deinit(self: *Inbound, io: Io) void {
        if (self.sockhash_manager) |*manager| manager.deinit();
        self.dataplane.deinit();
        self.listener6.deinit(io);
        self.listener4.deinit(io);
        self.* = undefined;
    }

    pub fn publisher(self: *Inbound) fakedns.Publisher {
        return self.dataplane.publisher();
    }

    pub fn attach(self: *Inbound, io: Io) !void {
        try self.dataplane.attach(io);
    }

    pub fn sockhashManager(self: *Inbound) ?*sockhash.Manager {
        return if (self.sockhash_manager) |*manager| manager else null;
    }

    pub fn refreshMonitoring(self: *const Inbound) void {
        const snapshot = self.dataplane.counterSnapshot() catch return;
        monitoring.registry.updateSkLookupCounters(
            snapshot.get(.lookup_hit),
            snapshot.get(.lookup_miss),
            snapshot.get(.pool_miss),
            snapshot.get(.assign4_success),
            snapshot.get(.assign4_error),
            snapshot.get(.assign6_success),
            snapshot.get(.assign6_error),
            snapshot.get(.pass),
            snapshot.get(.drop),
        );
    }

    pub fn run(
        self: *Inbound,
        dispatcher: session.Dispatcher,
        fake_dns: *fakedns.Store,
        io: Io,
        log_writer: *Io.Writer,
        log_mutex: *Io.Mutex,
    ) !void {
        monitoring.registry.listenerStarted();
        defer monitoring.registry.listenerStopped();
        {
            try log_mutex.lock(io);
            defer log_mutex.unlock(io);
            try log_writer.print(
                "sk_lookup inbound {s} attached in current netns; TCP listeners {f} and {f}\n",
                .{ self.inbound_tag orelse "-", self.listener4.socket.address, self.listener6.socket.address },
            );
            try log_writer.flush();
        }

        var group: Io.Group = .init;
        defer group.cancel(io);
        try group.concurrent(io, acceptLoop, .{ &self.listener4, .ip4, dispatcher, self.inbound_tag, fake_dns, self.literal_excluded_ips, self.literal_proxy_server_ips, &self.dataplane, io });
        try group.concurrent(io, acceptLoop, .{ &self.listener6, .ip6, dispatcher, self.inbound_tag, fake_dns, self.literal_excluded_ips, self.literal_proxy_server_ips, &self.dataplane, io });
        try group.await(io);
    }
};

fn enableTransparentListener(fd: std.posix.fd_t, family: net.IpAddress.Family) !void {
    const enabled: c_int = 1;
    const rc = switch (family) {
        .ip4 => linux.setsockopt(fd, linux.SOL.IP, linux.IP.TRANSPARENT, @ptrCast(&enabled), @sizeOf(c_int)),
        .ip6 => linux.setsockopt(fd, linux.SOL.IPV6, linux.IPV6.TRANSPARENT, @ptrCast(&enabled), @sizeOf(c_int)),
    };
    if (linux.errno(rc) != .SUCCESS) return error.SkLookupTransparentListenerFailed;
}

fn acceptLoop(
    listener: *net.Server,
    family: net.IpAddress.Family,
    dispatcher: session.Dispatcher,
    inbound_tag: ?[]const u8,
    fake_dns: *fakedns.Store,
    literal_excluded_ips: ?[]const config.IpRule,
    literal_proxy_server_ips: ?[]const config.IpRule,
    dataplane: *bpf.Dataplane,
    io: Io,
) Io.Cancelable!void {
    var group: Io.Group = .init;
    defer group.cancel(io);
    while (true) {
        const stream = listener.accept(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            else => return,
        };
        var warned = false;
        while (true) {
            group.concurrent(io, handleConnection, .{ stream, family, dispatcher, inbound_tag, fake_dns, literal_excluded_ips, literal_proxy_server_ips, dataplane, io }) catch {
                if (!warned) {
                    log.warn("sk_lookup inbound at worker capacity; queueing connection\n", .{});
                    warned = true;
                }
                io.sleep(Io.Duration.fromMilliseconds(10), .awake) catch |err| {
                    stream.close(io);
                    return err;
                };
                continue;
            };
            break;
        }
    }
}

fn handleConnection(
    stream: net.Stream,
    family: net.IpAddress.Family,
    dispatcher: session.Dispatcher,
    inbound_tag: ?[]const u8,
    fake_dns: *fakedns.Store,
    literal_excluded_ips: ?[]const config.IpRule,
    literal_proxy_server_ips: ?[]const config.IpRule,
    dataplane: *bpf.Dataplane,
    io: Io,
) Io.Cancelable!void {
    defer stream.close(io);
    const target = localDestination(stream, family) catch |err| {
        log.warn("sk_lookup inbound local destination failed: {s}\n", .{@errorName(err)});
        return;
    };
    if (fake_dns.lookup(target, io)) |lease_value| {
        var lease = lease_value;
        defer lease.release(io);
        const domain = lease.domain();
        const host = net.HostName.init(domain) catch return;
        dispatcher.dispatch(stream, skLookupDomainSession(host, target.getPort(), inbound_tag, domain, family), .{}, io) catch |err| {
            log.warn("sk_lookup dispatch failed: {s}\n", .{@errorName(err)});
        };
        return;
    }
    if (fake_dns.contains(target)) {
        log.warn("sk_lookup inbound rejected a FakeDNS-pool address without a live lease\n", .{});
        return;
    }
    const excluded_ips = literal_excluded_ips orelse {
        log.warn("sk_lookup inbound rejected an address without a live FakeDNS lease\n", .{});
        return;
    };
    if (matchesAny(target, excluded_ips) or matchesAny(target, literal_proxy_server_ips.?)) {
        log.warn("sk_lookup inbound rejected an excluded literal destination\n", .{});
        return;
    }
    const remote = remoteDestination(stream, family) catch {
        log.warn("sk_lookup inbound rejected a literal without peer identity\n", .{});
        return;
    };
    if (!literalAdmissionAuthorized(dataplane.consumeLiteralAdmission(target, remote, fakedns.monotonicNowNs(io)))) {
        log.warn("sk_lookup inbound rejected a literal without BPF admission proof\n", .{});
        return;
    }
    dispatcher.dispatch(stream, skLookupLiteralSession(target, inbound_tag, family), .{}, io) catch |err| {
        log.warn("sk_lookup dispatch failed: {s}\n", .{@errorName(err)});
    };
}

fn literalAdmissionAuthorized(bpf_proof: bool) bool {
    return bpf_proof;
}

fn matchesAny(target: net.IpAddress, rules: []const config.IpRule) bool {
    for (rules) |rule| if (rule.matches(target)) return true;
    return false;
}

fn skLookupDomainSession(
    host: net.HostName,
    port: u16,
    inbound_tag: ?[]const u8,
    domain: []const u8,
    family: net.IpAddress.Family,
) session.Session {
    return .{
        .target = .{ .host = .{ .name = host, .port = port } },
        .inbound_tag = inbound_tag,
        .sniffed_domain = domain,
        .preferred_family = family,
        .allow_sockhash_offload = true,
    };
}

fn skLookupLiteralSession(target: net.IpAddress, inbound_tag: ?[]const u8, family: net.IpAddress.Family) session.Session {
    return .{
        .target = .{ .address = target },
        .inbound_tag = inbound_tag,
        .sniffed_domain = null,
        .preferred_family = family,
        .allow_sockhash_offload = true,
    };
}

fn localDestination(stream: net.Stream, family: net.IpAddress.Family) !net.IpAddress {
    if (builtin.os.tag != .linux) return error.SkLookupRequiresLinux;
    return switch (family) {
        .ip4 => localDestination4(stream),
        .ip6 => localDestination6(stream),
    };
}

fn localDestination4(stream: net.Stream) !net.IpAddress {
    var address: linux.sockaddr.in = undefined;
    var length: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    const rc = linux.getsockname(stream.socket.handle, @ptrCast(&address), &length);
    if (linux.errno(rc) != .SUCCESS or length != @sizeOf(linux.sockaddr.in) or address.family != linux.AF.INET)
        return error.LocalDestinationUnavailable;
    return .{ .ip4 = .{
        .bytes = std.mem.asBytes(&address.addr)[0..4].*,
        .port = std.mem.bigToNative(u16, address.port),
    } };
}

fn localDestination6(stream: net.Stream) !net.IpAddress {
    var address: linux.sockaddr.in6 = undefined;
    var length: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    const rc = linux.getsockname(stream.socket.handle, @ptrCast(&address), &length);
    if (linux.errno(rc) != .SUCCESS or length != @sizeOf(linux.sockaddr.in6) or address.family != linux.AF.INET6)
        return error.LocalDestinationUnavailable;
    return .{ .ip6 = .{
        .bytes = address.addr,
        .port = std.mem.bigToNative(u16, address.port),
        .flow = address.flowinfo,
        .interface = .{ .index = address.scope_id },
    } };
}

fn remoteDestination(stream: net.Stream, family: net.IpAddress.Family) !net.IpAddress {
    return switch (family) {
        .ip4 => blk: {
            var address: linux.sockaddr.in = undefined;
            var length: linux.socklen_t = @sizeOf(linux.sockaddr.in);
            const rc = linux.getpeername(stream.socket.handle, @ptrCast(&address), &length);
            if (linux.errno(rc) != .SUCCESS or length != @sizeOf(linux.sockaddr.in) or address.family != linux.AF.INET) return error.RemoteDestinationUnavailable;
            break :blk .{ .ip4 = .{ .bytes = std.mem.asBytes(&address.addr)[0..4].*, .port = std.mem.bigToNative(u16, address.port) } };
        },
        .ip6 => blk: {
            var address: linux.sockaddr.in6 = undefined;
            var length: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
            const rc = linux.getpeername(stream.socket.handle, @ptrCast(&address), &length);
            if (linux.errno(rc) != .SUCCESS or length != @sizeOf(linux.sockaddr.in6) or address.family != linux.AF.INET6) return error.RemoteDestinationUnavailable;
            break :blk .{ .ip6 = .{ .bytes = address.addr, .port = std.mem.bigToNative(u16, address.port), .flow = address.flowinfo, .interface = .{ .index = address.scope_id } } };
        },
    };
}

test "converts getsockname IPv4 destination" {
    var address: linux.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, 8443), .addr = 0 };
    std.mem.asBytes(&address.addr).* = .{ 198, 18, 0, 1 };
    const target: net.IpAddress = .{ .ip4 = .{
        .bytes = std.mem.asBytes(&address.addr)[0..4].*,
        .port = std.mem.bigToNative(u16, address.port),
    } };
    try std.testing.expectEqual(@as(u16, 8443), target.getPort());
    try std.testing.expectEqualSlices(u8, &.{ 198, 18, 0, 1 }, &target.ip4.bytes);
}

test "only sk_lookup session factory authorizes SOCKHASH offload" {
    const host = try net.HostName.init("fake.test");
    const sess = skLookupDomainSession(host, 443, null, host.bytes, .ip4);
    try std.testing.expect(sess.allow_sockhash_offload);
    try std.testing.expectEqual(@as(u16, 443), sess.target.port());
}

test "IP literal session preserves address family tag and SOCKHASH eligibility" {
    const target = try net.IpAddress.parse("203.0.113.7", 8443);
    const sess = skLookupLiteralSession(target, "ebpf-in", .ip4);
    try std.testing.expect(sess.allow_sockhash_offload);
    try std.testing.expect(sess.sniffed_domain == null);
    try std.testing.expectEqual(net.IpAddress.Family.ip4, sess.preferred_family.?);
    try std.testing.expectEqualStrings("ebpf-in", sess.inbound_tag.?);
    try std.testing.expectEqual(target, sess.target.address);
}

test "literal exclusions cover local and proxy IPv4 and IPv6 ranges" {
    const rules = [_]config.IpRule{
        .{ .ip4 = .{ .bytes = .{ 192, 168, 8, 0 }, .prefix_len = 24 } },
        .{ .ip4 = .{ .bytes = .{ 203, 0, 113, 9 }, .prefix_len = 32 } },
        .{ .ip6 = .{ .bytes = .{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, .prefix_len = 10 } },
    };
    try std.testing.expect(matchesAny(try net.IpAddress.parse("192.168.8.1", 80), &rules));
    try std.testing.expect(matchesAny(try net.IpAddress.parse("203.0.113.9", 443), &rules));
    try std.testing.expect(matchesAny(try net.IpAddress.parse("fe80::1", 443), &rules));
    try std.testing.expect(!matchesAny(try net.IpAddress.parse("198.51.100.2", 443), &rules));
}

test "literal dispatch requires one-time BPF admission proof" {
    try std.testing.expect(!literalAdmissionAuthorized(false));
    try std.testing.expect(literalAdmissionAuthorized(true));
}
