const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../config/mod.zig");
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
const reality = @import("../transport/reality/client.zig");
const vless = @import("../proxy/vless/outbound.zig");

pub const Runtime = struct {
    cfg: *const config.Config,
    allocator: std.mem.Allocator,
    reactor_allocator: std.mem.Allocator = std.heap.page_allocator,
    raw_connection_limit: usize = 256,
    reactor: ?*raw_reactor.Reactor = null,

    pub fn run(self: *Runtime, io: Io, log_writer: *Io.Writer) !void {
        const dispatch_interface = self.dispatcher();

        var fake_dns_store: ?fakedns.Store = if (self.cfg.dns) |dns_cfg|
            if (dns_cfg.fake_dns) |fake_dns_cfg|
                try fakedns.Store.init(self.allocator, fake_dns_cfg)
            else
                null
        else
            null;
        defer if (fake_dns_store) |*store| store.deinit();

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
        self.reactor = &reactor;
        defer self.reactor = null;
        try group.concurrent(io, runRawReactor, .{&reactor});

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
            return error.UnsupportedInboundProtocol;
        }

        try group.await(io);
    }

    fn dispatcher(self: *Runtime) session.Dispatcher {
        return .{
            .context = self,
            .dispatch_fn = dispatchThunk,
        };
    }

    pub fn dispatch(self: *Runtime, client: net.Stream, sess: session.Session, preface: session.Preface, io: Io) !void {
        const outbound = if (sess.outbound_tag) |tag|
            self.cfg.findOutbound(tag) orelse return error.MissingOutboundTag
        else
            try routing.selectOutbound(self.cfg, sess);
        const reactor = self.reactor orelse return error.RuntimeNotRunning;
        if (std.mem.eql(u8, outbound.protocol, "freedom")) {
            const fake_dns_config: ?config.DnsConfig = if (self.cfg.dns) |dns_cfg|
                if (dns_cfg.fake_dns != null) dns_cfg else null
            else
                null;
            try freedom.handle(client, sess, preface, fake_dns_config, self.dispatcher(), reactor, io);
            return;
        }
        if (std.mem.eql(u8, outbound.protocol, "blackhole")) {
            try blackhole.handle(client, sess, preface, io);
            return;
        }
        if (std.mem.eql(u8, outbound.protocol, "dns")) {
            try dns_outbound.handle(client, sess, preface, self.cfg.dns, io);
            return;
        }
        if (std.mem.eql(u8, outbound.protocol, "vless")) {
            try vless.handle(outbound, client, sess, preface, reactor, io);
            return;
        }
        return error.UnsupportedOutboundProtocol;
    }
};

fn runRawReactor(reactor: *raw_reactor.Reactor) Io.Cancelable!void {
    try reactor.run();
}

fn runSocksInbound(inbound: config.Inbound, dispatcher: session.Dispatcher, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) Io.Cancelable!void {
    socks.run(inbound, dispatcher, io, log_writer, log_mutex) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn runRedirectInbound(inbound: config.Inbound, dispatcher: session.Dispatcher, fake_dns: ?*fakedns.Store, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) Io.Cancelable!void {
    redirect.run(inbound, dispatcher, fake_dns, io, log_writer, log_mutex) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn runDnsInbound(inbound: config.Inbound, dns_cfg: config.DnsConfig, fake_dns: ?*fakedns.Store, dispatcher: session.Dispatcher, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) Io.Cancelable!void {
    dns_inbound.run(inbound, dns_cfg, fake_dns, dispatcher, io, log_writer, log_mutex) catch |err| switch (err) {
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
