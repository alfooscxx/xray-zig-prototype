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

    pub fn init(
        inbound: config.Inbound,
        fake_dns_cfg: config.FakeDnsConfig,
        allocator: std.mem.Allocator,
        io: Io,
    ) !Inbound {
        if (builtin.os.tag != .linux) return error.SkLookupRequiresLinux;
        const settings = inbound.sk_lookup orelse return error.MissingSkLookupSettings;

        var address4 = net.IpAddress.parse(settings.listen4, settings.port4) catch return error.InvalidSkLookupListen4;
        var listener4 = try address4.listen(io, .{ .reuse_address = true });
        errdefer listener4.deinit(io);

        var address6 = net.IpAddress.parse(settings.listen6, settings.port6) catch return error.InvalidSkLookupListen6;
        var listener6 = try address6.listen(io, .{ .reuse_address = true });
        errdefer listener6.deinit(io);

        const dataplane = try bpf.Dataplane.init(
            settings.max_map_entries,
            listener4.socket.handle,
            listener6.socket.handle,
            fake_dns_cfg,
            settings.fake_dns_persistence,
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
            snapshot.get(.lookup_expiry),
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
        try group.concurrent(io, acceptLoop, .{ &self.listener4, .ip4, dispatcher, self.inbound_tag, fake_dns, io });
        try group.concurrent(io, acceptLoop, .{ &self.listener6, .ip6, dispatcher, self.inbound_tag, fake_dns, io });
        try group.await(io);
    }
};

fn acceptLoop(
    listener: *net.Server,
    family: net.IpAddress.Family,
    dispatcher: session.Dispatcher,
    inbound_tag: ?[]const u8,
    fake_dns: *fakedns.Store,
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
            group.concurrent(io, handleConnection, .{ stream, family, dispatcher, inbound_tag, fake_dns, io }) catch {
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
    io: Io,
) Io.Cancelable!void {
    defer stream.close(io);
    const target = localDestination(stream, family) catch |err| {
        log.warn("sk_lookup inbound local destination failed: {s}\n", .{@errorName(err)});
        return;
    };
    var lease = fake_dns.lookup(target, io) orelse {
        log.warn("sk_lookup inbound accepted an address without a live FakeDNS lease\n", .{});
        return;
    };
    defer lease.release(io);

    const domain = lease.domain();
    const host = net.HostName.init(domain) catch return;
    dispatcher.dispatch(stream, skLookupSession(host, target.getPort(), inbound_tag, domain, family), .{}, io) catch |err| {
        log.warn("sk_lookup dispatch failed: {s}\n", .{@errorName(err)});
    };
}

fn skLookupSession(
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
    const sess = skLookupSession(host, 443, null, host.bytes, .ip4);
    try std.testing.expect(sess.allow_sockhash_offload);
    try std.testing.expectEqual(@as(u16, 443), sess.target.port());
}
