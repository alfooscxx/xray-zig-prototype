const std = @import("std");

const config = @import("../config/mod.zig");
const session = @import("../net/session.zig");

pub const SelectError = error{
    MissingDefaultOutbound,
    MissingOutboundTag,
};

pub const Selection = struct {
    outbound: *const config.Outbound,
    rule_index: ?usize,
};

pub fn selectOutbound(cfg: *const config.Config, sess: session.Session) SelectError!*const config.Outbound {
    return (try selectOutboundWithMetadata(cfg, sess)).outbound;
}

pub fn selectOutboundWithMetadata(cfg: *const config.Config, sess: session.Session) SelectError!Selection {
    for (cfg.routing.rules, 0..) |rule, rule_index| {
        if (!ruleMatchesSession(rule, sess)) continue;
        return .{
            .outbound = cfg.findOutbound(rule.outbound_tag) orelse return error.MissingOutboundTag,
            .rule_index = rule_index,
        };
    }

    const tag = cfg.defaultOutboundTag() orelse return error.MissingDefaultOutbound;
    return .{
        .outbound = cfg.findOutbound(tag) orelse return error.MissingOutboundTag,
        .rule_index = null,
    };
}

fn ruleMatchesSession(rule: config.RouteRule, sess: session.Session) bool {
    if (rule.inbound_tags.len > 0) {
        const inbound_tag = sess.inbound_tag orelse return false;
        if (!ruleMatchesInboundTag(rule, inbound_tag)) return false;
    }

    if (rule.domains.len > 0) {
        const domain = sess.sniffed_domain orelse return false;
        if (!ruleMatchesDomain(rule, domain)) return false;
    }

    if (rule.ips.len > 0) {
        const address = switch (sess.target) {
            .address => |address| address,
            .host => return false,
        };
        if (!ruleMatchesIp(rule, address)) return false;
    }

    return true;
}

fn ruleMatchesInboundTag(rule: config.RouteRule, inbound_tag: []const u8) bool {
    for (rule.inbound_tags) |tag| {
        if (std.mem.eql(u8, tag, inbound_tag)) return true;
    }
    return false;
}

fn ruleMatchesDomain(rule: config.RouteRule, domain: []const u8) bool {
    for (rule.domains) |domain_rule| {
        if (domain_rule.matches(domain)) return true;
    }
    return false;
}

fn ruleMatchesIp(rule: config.RouteRule, address: std.Io.net.IpAddress) bool {
    for (rule.ips) |ip_rule| {
        if (ip_rule.matches(address)) return true;
    }
    return false;
}

test "selects matching domain route" {
    const source =
        \\{
        \\  "inbounds": [{"port": 1080, "protocol": "socks"}],
        \\  "outbounds": [
        \\    {"tag": "proxy", "protocol": "freedom"},
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ],
        \\  "routing": {
        \\    "defaultOutboundTag": "proxy",
        \\    "rules": [{"domain": ["domain:google.com"], "outboundTag": "direct"}]
        \\  }
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    const outbound = try selectOutbound(&cfg, .{
        .target = try session.targetFromHostBytes("example.com", 443),
        .sniffed_domain = "www.google.com",
    });
    try std.testing.expectEqualStrings("direct", outbound.tag.?);
}

test "selects matching inbound tag route" {
    const source =
        \\{
        \\  "inbounds": [{"tag": "dns-in", "port": 1053, "protocol": "dns"}],
        \\  "outbounds": [
        \\    {"tag": "proxy", "protocol": "freedom"},
        \\    {"tag": "dns-out", "protocol": "dns"}
        \\  ],
        \\  "routing": {
        \\    "defaultOutboundTag": "proxy",
        \\    "rules": [{"inboundTag": ["dns-in"], "outboundTag": "dns-out"}]
        \\  }
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    const outbound = try selectOutbound(&cfg, .{
        .target = try session.targetFromHostBytes("8.8.8.8", 53),
        .inbound_tag = "dns-in",
    });
    try std.testing.expectEqualStrings("dns-out", outbound.tag.?);
}

test "selects matching IP route" {
    const source =
        \\{
        \\  "inbounds": [{"port": 1080, "protocol": "socks"}],
        \\  "outbounds": [
        \\    {"tag": "proxy", "protocol": "freedom"},
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ],
        \\  "routing": {
        \\    "defaultOutboundTag": "proxy",
        \\    "rules": [{"ip": ["127.0.0.0/8", "2001:db8::/32"], "outboundTag": "direct"}]
        \\  }
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    const ipv4_outbound = try selectOutbound(&cfg, .{
        .target = try session.targetFromHostBytes("127.0.0.1", 80),
    });
    try std.testing.expectEqualStrings("direct", ipv4_outbound.tag.?);

    const ipv6_outbound = try selectOutbound(&cfg, .{
        .target = try session.targetFromHostBytes("2001:db8::1", 80),
    });
    try std.testing.expectEqualStrings("direct", ipv6_outbound.tag.?);
}

test "sk_lookup literals retain ordered IP inbound and default routing" {
    const source =
        \\{
        \\  "inbounds": [{"tag":"ebpf-in","protocol":"socks","listen":"127.0.0.1","port":1080}],
        \\  "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"proxy","protocol":"blackhole"}],
        \\  "routing": {"rules":[{"inboundTag":"ebpf-in","ip":["203.0.113.0/24","2001:db8::/32"],"outboundTag":"direct"}],"defaultOutboundTag":"proxy"}
        \\}
    ;
    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();
    const direct4 = try selectOutbound(&cfg, .{ .target = .{ .address = try std.Io.net.IpAddress.parse("203.0.113.7", 443) }, .inbound_tag = "ebpf-in", .preferred_family = .ip4 });
    const direct6 = try selectOutbound(&cfg, .{ .target = .{ .address = try std.Io.net.IpAddress.parse("2001:db8::7", 443) }, .inbound_tag = "ebpf-in", .preferred_family = .ip6 });
    const proxy = try selectOutbound(&cfg, .{ .target = .{ .address = try std.Io.net.IpAddress.parse("198.51.100.7", 443) }, .inbound_tag = "ebpf-in", .preferred_family = .ip4 });
    try std.testing.expectEqualStrings("direct", direct4.tag.?);
    try std.testing.expectEqualStrings("direct", direct6.tag.?);
    try std.testing.expectEqualStrings("proxy", proxy.tag.?);
}

test "falls back when IP route does not match" {
    const source =
        \\{
        \\  "inbounds": [{"port": 1080, "protocol": "socks"}],
        \\  "outbounds": [
        \\    {"tag": "proxy", "protocol": "freedom"},
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ],
        \\  "routing": {
        \\    "defaultOutboundTag": "proxy",
        \\    "rules": [{"ip": ["127.0.0.0/8"], "outboundTag": "direct"}]
        \\  }
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    const non_matching_ip = try selectOutbound(&cfg, .{
        .target = try session.targetFromHostBytes("192.168.1.1", 80),
    });
    try std.testing.expectEqualStrings("proxy", non_matching_ip.tag.?);

    const host_target = try selectOutbound(&cfg, .{
        .target = try session.targetFromHostBytes("example.com", 80),
    });
    try std.testing.expectEqualStrings("proxy", host_target.tag.?);
}

test "uses default route without domain match" {
    const source =
        \\{
        \\  "inbounds": [{"port": 1080, "protocol": "socks"}],
        \\  "outbounds": [{"tag": "proxy", "protocol": "freedom"}],
        \\  "routing": {"defaultOutboundTag": "proxy"}
        \\}
    ;

    var cfg = try config.parse(std.testing.allocator, source);
    defer cfg.deinit();

    const outbound = try selectOutbound(&cfg, .{
        .target = try session.targetFromHostBytes("example.com", 443),
        .sniffed_domain = "www.example.com",
    });
    try std.testing.expectEqualStrings("proxy", outbound.tag.?);
}
