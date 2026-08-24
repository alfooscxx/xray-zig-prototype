const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../config/mod.zig");
const control = @import("../control.zig");
const diagnostics = @import("../diagnostics.zig");
const log = @import("../log.zig");
const fakedns = @import("../dns/fakedns.zig");
const routing = @import("../routing/mod.zig");
const raw_reactor = @import("../net/reactor.zig");
const session = @import("../net/session.zig");
const dns_inbound = @import("../proxy/dns/inbound.zig");
const dns_outbound = @import("../proxy/dns/outbound.zig");
const blackhole = @import("../proxy/blackhole/outbound.zig");
const freedom = @import("../proxy/freedom/outbound.zig");
const redirect = @import("../proxy/redirect/inbound.zig");
const socks = @import("../proxy/socks/inbound.zig");
const sk_lookup = @import("../proxy/sk_lookup/inbound.zig");
const sockhash = @import("../proxy/sk_lookup/sockhash.zig");
const tun = @import("../proxy/tun/inbound.zig");
const reality = @import("../transport/reality/client.zig");
const vless = @import("../proxy/vless/outbound.zig");
const monitoring = @import("../monitoring.zig");

pub const Runtime = struct {
    cfg: *const config.Config,
    allocator: std.mem.Allocator,
    reactor_allocator: std.mem.Allocator = std.heap.page_allocator,
    raw_connection_limit: usize = 256,
    reality_handshake_slots: Io.Semaphore = .{ .permits = 32 },
    monitoring_enabled: bool = true,
    control_socket_path: []const u8 = control.default_socket_path,
    reactor: ?*raw_reactor.Reactor = null,
    sockhash_manager: ?*sockhash.Manager = null,
    sk_lookup_state: ?*sk_lookup.Inbound = null,

    pub fn run(self: *Runtime, io: Io, log_writer: *Io.Writer) !void {
        monitoring.registry.reset(
            self.cfg,
            self.monitoring_enabled,
            control.nowNs(io),
            self.raw_connection_limit,
        );
        const dispatch_interface = self.dispatcher();

        var sk_lookup_inbound: ?sk_lookup.Inbound = null;
        for (self.cfg.inbounds) |inbound| {
            if (!std.mem.eql(u8, inbound.protocol, "sk_lookup")) continue;
            const fake_dns_cfg = if (self.cfg.dns) |dns_cfg|
                dns_cfg.fake_dns orelse return error.MissingFakeDnsConfig
            else
                return error.MissingFakeDnsConfig;
            sk_lookup_inbound = try sk_lookup.Inbound.init(inbound, fake_dns_cfg, self.allocator, io);
            break;
        }
        defer if (sk_lookup_inbound) |*inbound| inbound.deinit(io);
        self.sk_lookup_state = if (sk_lookup_inbound) |*inbound| inbound else null;
        defer self.sk_lookup_state = null;

        const fake_dns_publisher: fakedns.Publisher = if (sk_lookup_inbound) |*inbound|
            inbound.publisher()
        else
            .{};

        var fake_dns_store: ?fakedns.Store = if (self.cfg.dns) |dns_cfg|
            if (dns_cfg.fake_dns) |fake_dns_cfg|
                try fakedns.Store.initRestored(
                    self.allocator,
                    fake_dns_cfg,
                    fake_dns_publisher,
                    fakedns.monotonicNowNs(io),
                )
            else
                null
        else
            null;
        defer if (fake_dns_store) |*store| store.deinit();

        if (sk_lookup_inbound) |*inbound| try inbound.attach(io);
        if (sk_lookup_inbound != null) {
            monitoring.registry.bpf_sk_lookup_up.store(true, .release);
            for (self.cfg.inbounds) |inbound| {
                if (!std.mem.eql(u8, inbound.protocol, "sk_lookup")) continue;
                const settings = inbound.sk_lookup.?;
                monitoring.registry.bpf_fake_capacity.store(settings.max_map_entries, .release);
                if (settings.fake_dns_persistence != null) {
                    monitoring.registry.fakedns_persistence_configured.store(true, .release);
                    monitoring.registry.fakedns_pin_compatible.store(true, .release);
                }
                break;
            }
        }
        defer monitoring.registry.bpf_sk_lookup_up.store(false, .release);

        var log_mutex: Io.Mutex = .init;
        var reactor = try raw_reactor.Reactor.init(
            self.reactor_allocator,
            io,
            self.raw_connection_limit,
        );
        defer reactor.deinit();
        var group: Io.Group = .init;
        defer {
            reactor.stop();
            group.cancel(io);
        }
        var raw_failure_buffer: [1]RawReactorFailure = undefined;
        var raw_failures: Io.Queue(RawReactorFailure) = .init(&raw_failure_buffer);
        defer raw_failures.close(io);
        self.reactor = &reactor;
        defer self.reactor = null;
        self.sockhash_manager = if (sk_lookup_inbound) |*inbound| inbound.sockhashManager() else null;
        defer self.sockhash_manager = null;
        try group.concurrent(io, runRawReactor, .{ &reactor, &raw_failures, io });
        if (self.sockhash_manager) |manager|
            try group.concurrent(io, runSockhashManager, .{manager});
        try group.concurrent(io, runControlServer, .{ control.Server{
            .path = self.control_socket_path,
            .dataplane = dataplaneName(self.cfg),
            .version = @import("../version.zig").string,
            .refresh_context = self,
            .refresh_fn = refreshMonitoring,
        }, io });

        for (self.cfg.inbounds) |inbound| {
            if (std.mem.eql(u8, inbound.protocol, "socks")) {
                try group.concurrent(io, runSocksInbound, .{ inbound, dispatch_interface, io, log_writer, &log_mutex });
                continue;
            }
            if (std.mem.eql(u8, inbound.protocol, "redirect")) {
                try group.concurrent(io, runRedirectInbound, .{ inbound, dispatch_interface, if (fake_dns_store) |*store| store else null, io, log_writer, &log_mutex });
                continue;
            }
            if (std.mem.eql(u8, inbound.protocol, "dns")) {
                const dns_cfg = self.cfg.dns orelse return error.MissingDnsConfig;
                try group.concurrent(io, runDnsInbound, .{ inbound, dns_cfg, if (fake_dns_store) |*store| store else null, dispatch_interface, io, log_writer, &log_mutex });
                continue;
            }
            if (std.mem.eql(u8, inbound.protocol, "tun")) {
                try group.concurrent(io, runTunInbound, .{ inbound, dispatch_interface, self.allocator, io, log_writer, &log_mutex });
                continue;
            }
            if (std.mem.eql(u8, inbound.protocol, "sk_lookup")) {
                const state = if (sk_lookup_inbound) |*value| value else return error.MissingSkLookupSettings;
                const store = if (fake_dns_store) |*value| value else return error.MissingFakeDnsConfig;
                try group.concurrent(io, runSkLookupInbound, .{ state, dispatch_interface, store, io, log_writer, &log_mutex });
                continue;
            }
            return error.UnsupportedInboundProtocol;
        }

        monitoring.registry.setReady(true, control.nowNs(io));
        defer monitoring.registry.setReady(false, control.nowNs(io));

        const raw_failure = raw_failures.getOne(io) catch |err| switch (err) {
            error.Canceled => return error.Canceled,
            error.Closed => unreachable,
        };
        return raw_failure.err;
    }

    fn dispatcher(self: *Runtime) session.Dispatcher {
        return .{
            .context = self,
            .dispatch_fn = dispatchThunk,
        };
    }

    pub fn dispatch(self: *Runtime, client: net.Stream, sess: session.Session, preface: session.Preface, io: Io) !void {
        monitoring.registry.connectionStart();
        var selected_tag: ?[]const u8 = null;
        var success = false;
        var active_stage: monitoring.ConnectionStage = .dispatch;
        defer monitoring.registry.connectionEnd(sess.inbound_tag, selected_tag, success, active_stage);
        const outbound = if (sess.outbound_tag) |tag| blk: {
            const selected = self.cfg.findOutbound(tag) orelse return error.MissingOutboundTag;
            monitoring.registry.routingDecision(selected.tag orelse selected.protocol, false);
            break :blk selected;
        } else blk: {
            const selection = try routing.selectOutboundWithMetadata(self.cfg, sess);
            monitoring.registry.routingDecision(selection.outbound.tag orelse selection.outbound.protocol, selection.rule_index != null);
            break :blk selection.outbound;
        };
        selected_tag = outbound.tag orelse outbound.protocol;
        monitoring.registry.connectionMoveToOutbound();
        active_stage = .outbound;
        const reactor = self.reactor orelse return error.RuntimeNotRunning;
        if (std.mem.eql(u8, outbound.protocol, "freedom")) {
            const fake_dns_config: ?config.DnsConfig = if (self.cfg.dns) |dns_cfg|
                if (dns_cfg.fake_dns != null) dns_cfg else null
            else
                null;
            try freedom.handle(
                client,
                sess,
                preface,
                fake_dns_config,
                self.dispatcher(),
                reactor,
                if (sess.allow_sockhash_offload) self.sockhash_manager else null,
                io,
            );
            success = true;
            return;
        }
        if (std.mem.eql(u8, outbound.protocol, "blackhole")) {
            try blackhole.handle(client, sess, preface, io);
            success = true;
            return;
        }
        if (std.mem.eql(u8, outbound.protocol, "dns")) {
            try dns_outbound.handle(client, sess, preface, self.cfg.dns, io);
            success = true;
            return;
        }
        if (std.mem.eql(u8, outbound.protocol, "vless")) {
            try vless.handle(
                outbound,
                client,
                sess,
                preface,
                reactor,
                &self.reality_handshake_slots,
                if (sess.allow_sockhash_offload) self.sockhash_manager else null,
                io,
            );
            success = true;
            return;
        }
        return error.UnsupportedOutboundProtocol;
    }
};

const RawReactorFailure = struct {
    err: anyerror,
};

fn runRawReactor(reactor: *raw_reactor.Reactor, failures: *Io.Queue(RawReactorFailure), io: Io) Io.Cancelable!void {
    diagnostics.setRawReactorCount(0);
    monitoring.registry.raw_reactor_up.store(true, .release);
    defer monitoring.registry.raw_reactor_up.store(false, .release);
    var failure: anyerror = error.RawReactorStopped;
    reactor.run() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => failure = err,
    };
    log.err("raw io_uring reactor stopped: {s}\n", .{@errorName(failure)});
    failures.putOne(io, .{ .err = failure }) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => return,
    };
}

fn refreshMonitoring(context: *anyopaque) void {
    const runtime: *Runtime = @ptrCast(@alignCast(context));
    if (runtime.sk_lookup_state) |inbound| inbound.refreshMonitoring();
    if (runtime.sockhash_manager) |manager| manager.refreshMonitoring();
}

fn runControlServer(server: control.Server, io: Io) Io.Cancelable!void {
    server.run(io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => {
            log.warn("control API stopped: {s}\n", .{@errorName(err)});
            return;
        },
    };
}

fn dataplaneName(cfg: *const config.Config) []const u8 {
    for (cfg.inbounds) |inbound| {
        if (std.mem.eql(u8, inbound.protocol, "sk_lookup")) return "sk_lookup";
        if (std.mem.eql(u8, inbound.protocol, "tun")) return "tun";
        if (std.mem.eql(u8, inbound.protocol, "redirect")) return "redirect";
    }
    return "userspace";
}

fn runSockhashManager(manager: *sockhash.Manager) Io.Cancelable!void {
    try manager.run();
}

fn runSocksInbound(inbound: config.Inbound, dispatcher: session.Dispatcher, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) Io.Cancelable!void {
    diagnostics.setThreadName("xz-socks-listen");
    socks.run(inbound, dispatcher, io, log_writer, log_mutex) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn runRedirectInbound(inbound: config.Inbound, dispatcher: session.Dispatcher, fake_dns: ?*fakedns.Store, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) Io.Cancelable!void {
    diagnostics.setThreadName("xz-redir-listen");
    redirect.run(inbound, dispatcher, fake_dns, io, log_writer, log_mutex) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn runDnsInbound(inbound: config.Inbound, dns_cfg: config.DnsConfig, fake_dns: ?*fakedns.Store, dispatcher: session.Dispatcher, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) Io.Cancelable!void {
    diagnostics.setThreadName("xz-dns-listen");
    dns_inbound.run(inbound, dns_cfg, fake_dns, dispatcher, io, log_writer, log_mutex) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn runTunInbound(inbound: config.Inbound, dispatcher: session.Dispatcher, allocator: std.mem.Allocator, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) Io.Cancelable!void {
    diagnostics.setThreadName("xz-tun-listen");
    tun.run(inbound, dispatcher, allocator, io, log_writer, log_mutex) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => log.err("tun inbound stopped: {s}\n", .{@errorName(err)}),
    };
}

fn runSkLookupInbound(inbound: *sk_lookup.Inbound, dispatcher: session.Dispatcher, fake_dns: *fakedns.Store, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) Io.Cancelable!void {
    diagnostics.setThreadName("xz-sk-lookup");
    inbound.run(dispatcher, fake_dns, io, log_writer, log_mutex) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn dispatchThunk(context: *anyopaque, client: net.Stream, sess: session.Session, preface: session.Preface, io: Io) anyerror!void {
    const runtime: *Runtime = @ptrCast(@alignCast(context));
    try runtime.dispatch(client, sess, preface, io);
}

pub fn validate(cfg: *const config.Config) !void {
    if (cfg.inbounds.len == 0) return error.MissingInbounds;

    var sk_lookup_count: usize = 0;
    for (cfg.inbounds) |inbound| {
        if (std.mem.eql(u8, inbound.protocol, "socks")) continue;
        if (std.mem.eql(u8, inbound.protocol, "redirect")) {
            if (builtin.os.tag != .linux) return error.RedirectRequiresLinux;
            continue;
        }
        if (std.mem.eql(u8, inbound.protocol, "dns")) {
            const dns_cfg = cfg.dns orelse return error.MissingDnsConfig;
            if (dns_cfg.servers.len == 0) return error.MissingDnsServers;
            continue;
        }
        if (std.mem.eql(u8, inbound.protocol, "tun")) {
            if (builtin.os.tag != .linux) return error.TunRequiresLinux;
            if (inbound.tun == null) return error.MissingTunSettings;
            continue;
        }
        if (std.mem.eql(u8, inbound.protocol, "sk_lookup")) {
            if (builtin.os.tag != .linux) return error.SkLookupRequiresLinux;
            if (inbound.sk_lookup == null) return error.MissingSkLookupSettings;
            if (cfg.dns == null or cfg.dns.?.fake_dns == null) return error.MissingFakeDnsConfig;
            sk_lookup_count += 1;
            if (sk_lookup_count > 1) return error.MultipleSkLookupInbounds;
            continue;
        }
        return error.UnsupportedInboundProtocol;
    }

    for (cfg.outbounds) |outbound| {
        if (outbound.tag == null) return error.MissingOutboundTag;
        if (std.mem.eql(u8, outbound.protocol, "freedom")) continue;
        if (std.mem.eql(u8, outbound.protocol, "blackhole")) continue;
        if (std.mem.eql(u8, outbound.protocol, "dns")) {
            const dns_cfg = cfg.dns orelse return error.MissingDnsConfig;
            if (dns_cfg.servers.len == 0) return error.MissingDnsServers;
            continue;
        }
        if (std.mem.eql(u8, outbound.protocol, "vless")) {
            try validateVlessOutbound(outbound);
            continue;
        }
        return error.UnsupportedOutboundProtocol;
    }

    for (cfg.inbounds) |inbound| {
        const transparent = if (inbound.sk_lookup) |settings| settings.transparent_intercept orelse continue else continue;
        for (cfg.outbounds) |outbound| {
            if (!std.mem.eql(u8, outbound.protocol, "vless")) continue;
            const vless_settings = switch (outbound.settings) {
                .vless => |settings| settings,
                .none => continue,
            };
            try validateTransparentProxyServer(transparent, vless_settings.address, vless_settings.port);
        }
    }

    const default_tag = cfg.routing.default_outbound_tag orelse return error.MissingDefaultOutbound;
    if (cfg.findOutbound(default_tag) == null) return error.MissingOutboundTag;

    for (cfg.routing.rules) |rule| {
        if (cfg.findOutbound(rule.outbound_tag) == null) return error.MissingOutboundTag;
    }

    if (cfg.dns) |dns_cfg| {
        for (dns_cfg.servers) |server| {
            const outbound = cfg.findOutbound(server.outbound_tag) orelse return error.MissingOutboundTag;
            if (!std.mem.eql(u8, outbound.protocol, "freedom") and
                !std.mem.eql(u8, outbound.protocol, "vless"))
            {
                return error.UnsupportedDnsResolverOutbound;
            }
        }
    }
}

fn validateTransparentProxyServer(transparent: config.TransparentInterceptSettings, address_text: []const u8, port: u16) !void {
    const address = net.IpAddress.parse(address_text, port) catch
        return error.TransparentProxyServerMustBeIpAddress;
    for (transparent.proxy_server_ips) |rule| if (rule.matches(address)) return;
    return error.UnprotectedTransparentProxyServer;
}

fn validateVlessOutbound(outbound: config.Outbound) !void {
    const settings = switch (outbound.settings) {
        .vless => |vless_settings| vless_settings,
        .none => return error.MissingVlessSettings,
    };

    _ = try vless.parseUuid(settings.id);
    if (settings.flow) |flow| {
        if (flow.len != 0 and !std.mem.eql(u8, flow, vless.vision.flow_name)) {
            return error.UnsupportedVlessFlow;
        }
    }

    if (!std.mem.eql(u8, outbound.stream.network, "tcp")) {
        return error.UnsupportedStreamNetwork;
    }

    const security = outbound.stream.security orelse return error.MissingRealitySettings;
    if (!std.mem.eql(u8, security, "reality")) {
        return error.UnsupportedStreamSecurity;
    }
    const reality_settings = outbound.stream.reality orelse return error.MissingRealitySettings;
    const parsed = try reality.parseSettings(reality_settings);
    if (!parsed.fingerprint.isFirefoxLike()) return error.UnsupportedTlsFingerprint;
}

test "validates supported SOCKS graph" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ],
        \\  "routing": {"defaultOutboundTag": "direct"}
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try validate(&cfg);
}

test "validates sk_lookup only with FakeDNS" {
    const source =
        \\{
        \\  "inbounds": [{
        \\    "tag": "ebpf-in", "protocol": "sk_lookup",
        \\    "settings": {"listen4":"0.0.0.0","port4":19080,"listen6":"::","port6":19081}
        \\  }],
        \\  "outbounds": [{"tag":"direct","protocol":"freedom"}],
        \\  "dns": {
        \\    "servers": [{"resolver":"1.1.1.1","outboundTag":"direct","domains":["domain:"]}],
        \\    "fakeDns": {}
        \\  },
        \\  "routing": {"defaultOutboundTag":"direct"}
        \\}
    ;
    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();
    try validate(&cfg);
}

test "rejects sk_lookup without FakeDNS" {
    const source =
        \\{
        \\  "inbounds": [{
        \\    "protocol": "sk_lookup",
        \\    "settings": {"listen4":"0.0.0.0","port4":19080,"listen6":"::","port6":19081}
        \\  }],
        \\  "outbounds": [{"tag":"direct","protocol":"freedom"}],
        \\  "routing": {"defaultOutboundTag":"direct"}
        \\}
    ;
    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();
    try std.testing.expectError(error.MissingFakeDnsConfig, validate(&cfg));
}

test "transparent interception requires an exact IP proxy-server exclusion" {
    const protected = [_]config.IpRule{.{ .ip4 = .{ .bytes = .{ 203, 0, 113, 9 }, .prefix_len = 32 } }};
    const transparent: config.TransparentInterceptSettings = .{
        .ingress_interface = "br-lan",
        .excluded_ips = &.{},
        .proxy_server_ips = @constCast(&protected),
    };
    try validateTransparentProxyServer(transparent, "203.0.113.9", 443);
    try std.testing.expectError(error.UnprotectedTransparentProxyServer, validateTransparentProxyServer(transparent, "203.0.113.10", 443));
    try std.testing.expectError(error.TransparentProxyServerMustBeIpAddress, validateTransparentProxyServer(transparent, "proxy.example", 443));
}

test "validates redirect VLESS Reality graph" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "redir", "listen": "127.0.0.1", "port": 12345, "protocol": "redirect"}
        \\  ],
        \\  "outbounds": [
        \\    {
        \\      "tag": "proxy",
        \\      "protocol": "vless",
        \\      "settings": {
        \\        "vnext": [
        \\          {
        \\            "address": "proxy.example.com",
        \\            "port": 443,
        \\            "users": [{"id": "00000000-0000-0000-0000-000000000000"}]
        \\          }
        \\        ]
        \\      },
        \\      "streamSettings": {
        \\        "network": "tcp",
        \\        "security": "reality",
        \\        "realitySettings": {
        \\          "serverName": "www.example.com",
        \\          "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        \\          "shortId": "0123456789abcdef",
        \\          "fingerprint": "firefox"
        \\        }
        \\      }
        \\    },
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ],
        \\  "routing": {
        \\    "defaultOutboundTag": "proxy",
        \\    "rules": [
        \\      {"domain": ["domain:google.com"], "outboundTag": "direct"}
        \\    ]
        \\  }
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try validate(&cfg);
}

test "validates VLESS Reality with Vision flow" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {
        \\      "tag": "proxy",
        \\      "protocol": "vless",
        \\      "settings": {
        \\        "address": "proxy.example.com",
        \\        "port": 443,
        \\        "id": "00000000-0000-0000-0000-000000000000",
        \\        "flow": "xtls-rprx-vision"
        \\      },
        \\      "streamSettings": {
        \\        "network": "tcp",
        \\        "security": "reality",
        \\        "realitySettings": {
        \\          "serverName": "www.example.com",
        \\          "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        \\          "shortId": "0123456789abcdef",
        \\          "fingerprint": "firefox"
        \\        }
        \\      }
        \\    }
        \\  ],
        \\  "routing": {"defaultOutboundTag": "proxy"}
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try validate(&cfg);
}

test "rejects unsupported VLESS Vision udp443 flow" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {
        \\      "tag": "proxy",
        \\      "protocol": "vless",
        \\      "settings": {
        \\        "address": "proxy.example.com",
        \\        "port": 443,
        \\        "id": "00000000-0000-0000-0000-000000000000",
        \\        "flow": "xtls-rprx-vision-udp443"
        \\      },
        \\      "streamSettings": {
        \\        "network": "tcp",
        \\        "security": "reality",
        \\        "realitySettings": {
        \\          "serverName": "www.example.com",
        \\          "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        \\          "shortId": "0123456789abcdef",
        \\          "fingerprint": "firefox"
        \\        }
        \\      }
        \\    }
        \\  ],
        \\  "routing": {"defaultOutboundTag": "proxy"}
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectError(error.UnsupportedVlessFlow, validate(&cfg));
}

test "validates dns inbound with configured upstream" {
    const source =
        \\{
        \\  "dns": {
        \\    "servers": [
        \\      {"resolver": "1.1.1.1:53", "outboundTag": "direct", "domains": ["domain:"]}
        \\    ]
        \\  },
        \\  "inbounds": [
        \\    {"tag": "dns-in", "listen": "127.0.0.1", "port": 1053, "protocol": "dns"},
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ],
        \\  "routing": {"defaultOutboundTag": "direct"}
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try validate(&cfg);
}

test "validates blackhole and dns outbounds" {
    const source =
        \\{
        \\  "dns": {
        \\    "servers": [
        \\      {"resolver": "1.1.1.1", "outboundTag": "proxy", "domains": ["domain:"]}
        \\    ]
        \\  },
        \\  "inbounds": [
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {"tag": "proxy", "protocol": "freedom"},
        \\    {"tag": "block", "protocol": "blackhole"},
        \\    {"tag": "dns-out", "protocol": "dns"}
        \\  ],
        \\  "routing": {
        \\    "defaultOutboundTag": "proxy",
        \\    "rules": [
        \\      {"inboundTag": ["socks-in"], "domain": ["domain:block.example"], "outboundTag": "block"}
        \\    ]
        \\  }
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try validate(&cfg);
}

test "rejects dns resolver routed through dns outbound" {
    const source =
        \\{
        \\  "dns": {
        \\    "servers": [
        \\      {"resolver": "1.1.1.1", "outboundTag": "dns-out", "domains": ["domain:"]}
        \\    ]
        \\  },
        \\  "inbounds": [
        \\    {"tag": "dns-in", "listen": "127.0.0.1", "port": 1053, "protocol": "dns"}
        \\  ],
        \\  "outbounds": [
        \\    {"tag": "direct", "protocol": "freedom"},
        \\    {"tag": "dns-out", "protocol": "dns"}
        \\  ],
        \\  "routing": {"defaultOutboundTag": "direct"}
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectError(error.UnsupportedDnsResolverOutbound, validate(&cfg));
}

test "rejects missing explicit default outbound tag" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ]
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectError(error.MissingDefaultOutbound, validate(&cfg));
}

test "rejects untagged outbounds" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {"protocol": "freedom"}
        \\  ],
        \\  "routing": {"defaultOutboundTag": "direct"}
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectError(error.MissingOutboundTag, validate(&cfg));
}

test "rejects dns inbound without dns config" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "dns-in", "listen": "127.0.0.1", "port": 1053, "protocol": "dns"}
        \\  ],
        \\  "outbounds": [
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ]
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectError(error.MissingDnsConfig, validate(&cfg));
}

test "rejects non-Firefox Reality fingerprint until implemented" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {
        \\      "tag": "proxy",
        \\      "protocol": "vless",
        \\      "settings": {
        \\        "address": "proxy.example.com",
        \\        "port": 443,
        \\        "id": "00000000-0000-0000-0000-000000000000"
        \\      },
        \\      "streamSettings": {
        \\        "network": "tcp",
        \\        "security": "reality",
        \\        "realitySettings": {
        \\          "serverName": "www.example.com",
        \\          "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        \\          "shortId": "0123456789abcdef",
        \\          "fingerprint": "chrome"
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectError(error.UnsupportedTlsFingerprint, validate(&cfg));
}
