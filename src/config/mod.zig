const std = @import("std");
const net = std.Io.net;
const tls_cipher_policy = @import("../transport/tls/cipher_policy.zig");
const tls_fingerprint = @import("../transport/tls/fingerprint.zig");

pub const Config = struct {
    allocator: std.mem.Allocator,
    inbounds: []Inbound,
    outbounds: []Outbound,
    dns: ?DnsConfig,
    routing: Routing,

    pub fn deinit(self: *Config) void {
        for (self.inbounds) |*inbound| inbound.deinit(self.allocator);
        for (self.outbounds) |*outbound| outbound.deinit(self.allocator);
        if (self.dns) |*dns| dns.deinit(self.allocator);
        self.routing.deinit(self.allocator);
        self.allocator.free(self.inbounds);
        self.allocator.free(self.outbounds);
        self.* = undefined;
    }

    pub fn defaultOutboundTag(self: *const Config) ?[]const u8 {
        return self.routing.default_outbound_tag;
    }

    pub fn findOutbound(self: *const Config, tag: []const u8) ?*const Outbound {
        for (self.outbounds) |*outbound| {
            if (outbound.tag) |outbound_tag| {
                if (std.mem.eql(u8, outbound_tag, tag)) return outbound;
            }
        }
        return null;
    }
};

pub const Inbound = struct {
    tag: ?[]const u8,
    listen: []const u8,
    port: u16,
    protocol: []const u8,

    pub fn deinit(self: *Inbound, allocator: std.mem.Allocator) void {
        if (self.tag) |tag| allocator.free(tag);
        allocator.free(self.listen);
        allocator.free(self.protocol);
        self.* = undefined;
    }
};

pub const Outbound = struct {
    tag: ?[]const u8,
    protocol: []const u8,
    settings: OutboundSettings,
    stream: StreamSettings,

    pub fn deinit(self: *Outbound, allocator: std.mem.Allocator) void {
        if (self.tag) |tag| allocator.free(tag);
        allocator.free(self.protocol);
        self.settings.deinit(allocator);
        self.stream.deinit(allocator);
        self.* = undefined;
    }
};

pub const OutboundSettings = union(enum) {
    none,
    vless: VlessOutboundSettings,

    pub fn deinit(self: *OutboundSettings, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .none => {},
            .vless => |*settings| settings.deinit(allocator),
        }
    }
};

pub const VlessOutboundSettings = struct {
    address: []const u8,
    port: u16,
    id: []const u8,
    flow: ?[]const u8,

    pub fn deinit(self: *VlessOutboundSettings, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
        allocator.free(self.id);
        if (self.flow) |flow| allocator.free(flow);
        self.* = undefined;
    }
};

pub const StreamSettings = struct {
    network: []const u8,
    security: ?[]const u8,
    reality: ?RealitySettings,

    pub fn deinit(self: *StreamSettings, allocator: std.mem.Allocator) void {
        allocator.free(self.network);
        if (self.security) |security| allocator.free(security);
        if (self.reality) |*reality| reality.deinit(allocator);
        self.* = undefined;
    }
};

pub const RealitySettings = struct {
    server_name: []const u8,
    public_key: []const u8,
    short_id: []const u8,
    fingerprint: tls_fingerprint.Fingerprint,
    cipher_policy: tls_cipher_policy.CipherPolicy = tls_cipher_policy.default_policy,

    pub fn deinit(self: *RealitySettings, allocator: std.mem.Allocator) void {
        allocator.free(self.server_name);
        allocator.free(self.public_key);
        allocator.free(self.short_id);
        self.* = undefined;
    }
};

pub const DnsConfig = struct {
    servers: []DnsServer,
    fake_dns: ?FakeDnsConfig,

    pub fn deinit(self: *DnsConfig, allocator: std.mem.Allocator) void {
        for (self.servers) |*server| server.deinit(allocator);
        allocator.free(self.servers);
        if (self.fake_dns) |*fake_dns| fake_dns.deinit(allocator);
        self.* = undefined;
    }

    pub fn selectServer(self: DnsConfig, domain: []const u8) *const DnsServer {
        for (self.servers) |*server| {
            if (server.matches(domain)) return server;
        }
        return &self.servers[self.servers.len - 1];
    }
};

pub const DnsServer = struct {
    resolver: []const u8,
    outbound_tag: []const u8,
    domains: []DomainRule,

    pub fn deinit(self: *DnsServer, allocator: std.mem.Allocator) void {
        allocator.free(self.resolver);
        allocator.free(self.outbound_tag);
        for (self.domains) |*domain| domain.deinit(allocator);
        allocator.free(self.domains);
        self.* = undefined;
    }

    pub fn matches(self: DnsServer, domain: []const u8) bool {
        for (self.domains) |rule| {
            if (rule.matches(domain)) return true;
        }
        return false;
    }
};

pub const FakeDnsConfig = struct {
    ip_pool: []const u8,
    ip_pool6: []const u8,
    ttl: u32,

    pub fn deinit(self: *FakeDnsConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.ip_pool);
        allocator.free(self.ip_pool6);
        self.* = undefined;
    }
};

pub const Routing = struct {
    default_outbound_tag: ?[]const u8,
    rules: []RouteRule,

    pub fn deinit(self: *Routing, allocator: std.mem.Allocator) void {
        if (self.default_outbound_tag) |tag| allocator.free(tag);
        for (self.rules) |*rule| rule.deinit(allocator);
        allocator.free(self.rules);
        self.* = undefined;
    }
};

pub const RouteRule = struct {
    inbound_tags: []const []const u8,
    domains: []DomainRule,
    ips: []IpRule,
    outbound_tag: []const u8,

    pub fn deinit(self: *RouteRule, allocator: std.mem.Allocator) void {
        for (self.inbound_tags) |tag| allocator.free(tag);
        allocator.free(self.inbound_tags);
        for (self.domains) |*domain| domain.deinit(allocator);
        allocator.free(self.domains);
        allocator.free(self.ips);
        allocator.free(self.outbound_tag);
        self.* = undefined;
    }
};

pub const DomainRule = struct {
    pattern: []const u8,

    pub fn deinit(self: *DomainRule, allocator: std.mem.Allocator) void {
        allocator.free(self.pattern);
        self.* = undefined;
    }

    pub fn matches(self: DomainRule, host: []const u8) bool {
        const pattern = stripDomainPrefix(self.pattern);
        if (pattern.len == 0) return true;
        if (std.ascii.eqlIgnoreCase(host, pattern)) return true;
        if (host.len <= pattern.len) return false;
        if (!std.ascii.endsWithIgnoreCase(host, pattern)) return false;
        return host[host.len - pattern.len - 1] == '.';
    }
};

pub const IpRule = union(enum) {
    ip4: Cidr4,
    ip6: Cidr6,

    pub fn matches(self: IpRule, address: net.IpAddress) bool {
        return switch (self) {
            .ip4 => |rule| switch (address) {
                .ip4 => |ip4| matchesPrefix(&ip4.bytes, &rule.bytes, rule.prefix_len),
                .ip6 => false,
            },
            .ip6 => |rule| switch (address) {
                .ip4 => false,
                .ip6 => |ip6| matchesPrefix(&ip6.bytes, &rule.bytes, rule.prefix_len),
            },
        };
    }
};

pub const Cidr4 = struct {
    bytes: [4]u8,
    prefix_len: u8,
};

pub const Cidr6 = struct {
    bytes: [16]u8,
    prefix_len: u8,
};

fn matchesPrefix(address: []const u8, network: []const u8, prefix_len: u8) bool {
    const full_bytes = prefix_len / 8;
    if (!std.mem.eql(u8, address[0..full_bytes], network[0..full_bytes])) return false;

    const remaining_bits = prefix_len % 8;
    if (remaining_bits == 0) return true;

    const shift: u3 = @intCast(8 - remaining_bits);
    const mask: u8 = @as(u8, 0xff) << shift;
    return (address[full_bytes] & mask) == (network[full_bytes] & mask);
}

pub const ParseConfigError = error{
    RootMustBeObject,
    InboundsMustBeArray,
    OutboundsMustBeArray,
    RoutingMustBeObject,
    RulesMustBeArray,
    RuleMustBeObject,
    RuleInboundTagMustBeStringOrArray,
    RuleDomainMustBeStringOrArray,
    RuleIpMustBeStringOrArray,
    InboundMustBeObject,
    OutboundMustBeObject,
    SettingsMustBeObject,
    StreamSettingsMustBeObject,
    RealitySettingsMustBeObject,
    DnsMustBeObject,
    DnsServersMustBeArray,
    DnsServerMustBeObject,
    DnsServerDomainsMustBeArray,
    FakeDnsMustBeObject,
    VnextMustBeArray,
    VnextMustContainServer,
    VnextServerMustBeObject,
    UsersMustBeArray,
    UsersMustContainUser,
    UserMustBeObject,
    MissingInboundPort,
    MissingInboundProtocol,
    MissingOutboundProtocol,
    MissingVlessAddress,
    MissingVlessPort,
    MissingVlessUserId,
    MissingRealityServerName,
    MissingRealityPublicKey,
    MissingRealityShortId,
    MissingDnsServers,
    MissingDnsResolver,
    MissingDnsOutboundTag,
    MissingDnsServerDomains,
    MissingDnsFallbackServer,
    MissingRouteOutboundTag,
    InvalidPort,
    InvalidDnsTtl,
    UnsupportedPortFormat,
    UnsupportedIpRule,
    FieldMustBeString,
    UnsupportedTlsFingerprint,
    UnsupportedTlsCipherPolicy,
};

pub fn parse(allocator: std.mem.Allocator, bytes: []const u8) !Config {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return error.RootMustBeObject;
    const root = &parsed.value.object;

    var inbounds: std.ArrayList(Inbound) = .empty;
    errdefer deinitInboundList(allocator, &inbounds);

    if (root.get("inbounds")) |inbounds_value| {
        if (inbounds_value != .array) return error.InboundsMustBeArray;
        for (inbounds_value.array.items) |item| {
            try inbounds.append(allocator, try parseInbound(allocator, item));
        }
    }

    var outbounds: std.ArrayList(Outbound) = .empty;
    errdefer deinitOutboundList(allocator, &outbounds);

    if (root.get("outbounds")) |outbounds_value| {
        if (outbounds_value != .array) return error.OutboundsMustBeArray;
        for (outbounds_value.array.items) |item| {
            try outbounds.append(allocator, try parseOutbound(allocator, item));
        }
    }

    var routing = try parseRouting(allocator, root.get("routing"));
    errdefer routing.deinit(allocator);

    var dns = try parseDns(allocator, root.get("dns"));
    errdefer if (dns) |*owned| owned.deinit(allocator);

    const owned_inbounds = try inbounds.toOwnedSlice(allocator);
    errdefer deinitInboundSlice(allocator, owned_inbounds);

    const owned_outbounds = try outbounds.toOwnedSlice(allocator);
    errdefer deinitOutboundSlice(allocator, owned_outbounds);

    return .{
        .allocator = allocator,
        .inbounds = owned_inbounds,
        .outbounds = owned_outbounds,
        .dns = dns,
        .routing = routing,
    };
}

fn parseInbound(allocator: std.mem.Allocator, value: std.json.Value) !Inbound {
    if (value != .object) return error.InboundMustBeObject;
    const object = &value.object;

    const protocol = try requiredString(allocator, object, "protocol", error.MissingInboundProtocol);
    errdefer allocator.free(protocol);

    const listen = try optionalString(allocator, object, "listen") orelse try allocator.dupe(u8, "127.0.0.1");
    errdefer allocator.free(listen);

    const tag = try optionalString(allocator, object, "tag");
    errdefer if (tag) |owned| allocator.free(owned);

    return .{
        .tag = tag,
        .listen = listen,
        .port = try requiredPort(object, "port", error.MissingInboundPort),
        .protocol = protocol,
    };
}

fn parseOutbound(allocator: std.mem.Allocator, value: std.json.Value) !Outbound {
    if (value != .object) return error.OutboundMustBeObject;
    const object = &value.object;

    const protocol = try requiredString(allocator, object, "protocol", error.MissingOutboundProtocol);
    errdefer allocator.free(protocol);

    const tag = try optionalString(allocator, object, "tag");
    errdefer if (tag) |owned| allocator.free(owned);

    var settings: OutboundSettings = if (std.mem.eql(u8, protocol, "vless"))
        .{ .vless = try parseVlessOutboundSettings(allocator, object.get("settings")) }
    else
        .none;
    errdefer settings.deinit(allocator);

    var stream = try parseStreamSettings(allocator, object.get("streamSettings"));
    errdefer stream.deinit(allocator);

    return .{
        .tag = tag,
        .protocol = protocol,
        .settings = settings,
        .stream = stream,
    };
}

fn parseVlessOutboundSettings(allocator: std.mem.Allocator, maybe_value: ?std.json.Value) !VlessOutboundSettings {
    const value = maybe_value orelse return error.SettingsMustBeObject;
    if (value != .object) return error.SettingsMustBeObject;
    const object = &value.object;

    if (object.get("vnext")) |vnext_value| {
        if (vnext_value != .array) return error.VnextMustBeArray;
        if (vnext_value.array.items.len == 0) return error.VnextMustContainServer;
        const server_value = vnext_value.array.items[0];
        if (server_value != .object) return error.VnextServerMustBeObject;
        const server = &server_value.object;

        const address = try requiredString(allocator, server, "address", error.MissingVlessAddress);
        errdefer allocator.free(address);

        const users_value = server.get("users") orelse return error.UsersMustContainUser;
        if (users_value != .array) return error.UsersMustBeArray;
        if (users_value.array.items.len == 0) return error.UsersMustContainUser;
        const user_value = users_value.array.items[0];
        if (user_value != .object) return error.UserMustBeObject;
        const user = &user_value.object;

        const id = try requiredString(allocator, user, "id", error.MissingVlessUserId);
        errdefer allocator.free(id);

        const flow = try optionalString(allocator, user, "flow");
        errdefer if (flow) |owned| allocator.free(owned);

        return .{
            .address = address,
            .port = try requiredPort(server, "port", error.MissingVlessPort),
            .id = id,
            .flow = flow,
        };
    }

    const address = try requiredString(allocator, object, "address", error.MissingVlessAddress);
    errdefer allocator.free(address);
    const id = try requiredString(allocator, object, "id", error.MissingVlessUserId);
    errdefer allocator.free(id);
    const flow = try optionalString(allocator, object, "flow");
    errdefer if (flow) |owned| allocator.free(owned);

    return .{
        .address = address,
        .port = try requiredPort(object, "port", error.MissingVlessPort),
        .id = id,
        .flow = flow,
    };
}

fn parseStreamSettings(allocator: std.mem.Allocator, maybe_value: ?std.json.Value) !StreamSettings {
    const value = maybe_value orelse return .{
        .network = try allocator.dupe(u8, "tcp"),
        .security = null,
        .reality = null,
    };
    if (value != .object) return error.StreamSettingsMustBeObject;
    const object = &value.object;

    const network = try optionalString(allocator, object, "network") orelse try allocator.dupe(u8, "tcp");
    errdefer allocator.free(network);

    const security = try optionalString(allocator, object, "security");
    errdefer if (security) |owned| allocator.free(owned);

    const reality = if (object.get("realitySettings")) |reality_value|
        try parseRealitySettings(allocator, reality_value)
    else
        null;
    errdefer if (reality) |*owned| owned.deinit(allocator);

    return .{
        .network = network,
        .security = security,
        .reality = reality,
    };
}

fn parseRealitySettings(allocator: std.mem.Allocator, value: std.json.Value) !RealitySettings {
    if (value != .object) return error.RealitySettingsMustBeObject;
    const object = &value.object;

    const server_name = try requiredString(allocator, object, "serverName", error.MissingRealityServerName);
    errdefer allocator.free(server_name);
    const public_key = try requiredString(allocator, object, "publicKey", error.MissingRealityPublicKey);
    errdefer allocator.free(public_key);
    const short_id = try requiredString(allocator, object, "shortId", error.MissingRealityShortId);
    errdefer allocator.free(short_id);
    const fingerprint_text = try optionalString(allocator, object, "fingerprint");
    defer if (fingerprint_text) |owned| allocator.free(owned);
    const cipher_policy_text = try optionalString(allocator, object, "cipherPolicy");
    defer if (cipher_policy_text) |owned| allocator.free(owned);

    return .{
        .server_name = server_name,
        .public_key = public_key,
        .short_id = short_id,
        .fingerprint = try tls_fingerprint.parse(fingerprint_text),
        .cipher_policy = try tls_cipher_policy.parse(cipher_policy_text),
    };
}

fn parseDns(allocator: std.mem.Allocator, maybe_value: ?std.json.Value) !?DnsConfig {
    const value = maybe_value orelse return null;
    if (value != .object) return error.DnsMustBeObject;
    const object = &value.object;

    const servers_value = object.get("servers") orelse return error.MissingDnsServers;
    if (servers_value != .array) return error.DnsServersMustBeArray;

    var servers: std.ArrayList(DnsServer) = .empty;
    errdefer deinitDnsServerList(allocator, &servers);
    for (servers_value.array.items) |item| {
        try servers.append(allocator, try parseDnsServer(allocator, item));
    }

    if (servers.items.len == 0) return error.MissingDnsServers;
    if (!isDnsFallbackServer(servers.items[servers.items.len - 1])) return error.MissingDnsFallbackServer;

    const fake_dns = try parseFakeDns(allocator, object.get("fakeDns"));
    errdefer if (fake_dns) |owned_value| {
        var owned = owned_value;
        owned.deinit(allocator);
    };

    return .{
        .servers = try servers.toOwnedSlice(allocator),
        .fake_dns = fake_dns,
    };
}

fn parseDnsServer(allocator: std.mem.Allocator, value: std.json.Value) !DnsServer {
    if (value != .object) return error.DnsServerMustBeObject;
    const object = &value.object;

    const resolver = try requiredString(allocator, object, "resolver", error.MissingDnsResolver);
    errdefer allocator.free(resolver);
    const outbound_tag = try requiredString(allocator, object, "outboundTag", error.MissingDnsOutboundTag);
    errdefer allocator.free(outbound_tag);

    const domains_value = object.get("domains") orelse return error.MissingDnsServerDomains;
    if (domains_value != .array) return error.DnsServerDomainsMustBeArray;
    if (domains_value.array.items.len == 0) return error.MissingDnsServerDomains;

    var domains: std.ArrayList(DomainRule) = .empty;
    errdefer deinitDomainRuleList(allocator, &domains);
    for (domains_value.array.items) |item| {
        if (item != .string) return error.RuleDomainMustBeStringOrArray;
        try appendDomainRule(allocator, &domains, item.string);
    }

    return .{
        .resolver = resolver,
        .outbound_tag = outbound_tag,
        .domains = try domains.toOwnedSlice(allocator),
    };
}

fn isDnsFallbackServer(server: DnsServer) bool {
    return server.domains.len == 1 and std.mem.eql(u8, server.domains[0].pattern, "domain:");
}

fn parseFakeDns(allocator: std.mem.Allocator, maybe_value: ?std.json.Value) !?FakeDnsConfig {
    const default_pool = "198.18.0.0/15";
    const default_pool6 = "fc00::/18";
    const value = maybe_value orelse return null;
    if (value != .object) return error.FakeDnsMustBeObject;
    const object = &value.object;

    const ip_pool = try optionalString(allocator, object, "ipPool") orelse try allocator.dupe(u8, default_pool);
    errdefer allocator.free(ip_pool);
    const ip_pool6 = try optionalString(allocator, object, "ipPool6") orelse try allocator.dupe(u8, default_pool6);
    errdefer allocator.free(ip_pool6);

    const ttl: u32 = if (object.get("ttl")) |ttl_value| switch (ttl_value) {
        .integer => |integer| blk: {
            if (integer < 0 or integer > std.math.maxInt(u32)) return error.InvalidDnsTtl;
            break :blk @intCast(integer);
        },
        else => return error.InvalidDnsTtl,
    } else 60;

    return .{
        .ip_pool = ip_pool,
        .ip_pool6 = ip_pool6,
        .ttl = ttl,
    };
}

fn parseRouting(allocator: std.mem.Allocator, maybe_value: ?std.json.Value) !Routing {
    const empty_rules = try allocator.alloc(RouteRule, 0);
    errdefer allocator.free(empty_rules);

    const value = maybe_value orelse return .{
        .default_outbound_tag = null,
        .rules = empty_rules,
    };
    if (value != .object) return error.RoutingMustBeObject;
    const object = &value.object;

    const default_outbound_tag = try optionalString(allocator, object, "defaultOutboundTag");
    errdefer if (default_outbound_tag) |tag| allocator.free(tag);

    var rules: std.ArrayList(RouteRule) = .empty;
    errdefer deinitRouteRuleList(allocator, &rules);

    if (object.get("rules")) |rules_value| {
        if (rules_value != .array) return error.RulesMustBeArray;
        for (rules_value.array.items) |item| {
            try rules.append(allocator, try parseRouteRule(allocator, item));
        }
    }

    const owned_rules = try rules.toOwnedSlice(allocator);
    errdefer deinitRouteRuleSlice(allocator, owned_rules);
    allocator.free(empty_rules);

    return .{
        .default_outbound_tag = default_outbound_tag,
        .rules = owned_rules,
    };
}

fn parseRouteRule(allocator: std.mem.Allocator, value: std.json.Value) !RouteRule {
    if (value != .object) return error.RuleMustBeObject;
    const object = &value.object;

    const outbound_tag = try requiredString(allocator, object, "outboundTag", error.MissingRouteOutboundTag);
    errdefer allocator.free(outbound_tag);

    var inbound_tags: std.ArrayList([]const u8) = .empty;
    errdefer deinitStringList(allocator, &inbound_tags);

    if (object.get("inboundTag")) |tag_value| {
        switch (tag_value) {
            .string => |tag| try appendString(allocator, &inbound_tags, tag),
            .array => |array| {
                for (array.items) |item| {
                    if (item != .string) return error.RuleInboundTagMustBeStringOrArray;
                    try appendString(allocator, &inbound_tags, item.string);
                }
            },
            else => return error.RuleInboundTagMustBeStringOrArray,
        }
    }

    var domains: std.ArrayList(DomainRule) = .empty;
    errdefer deinitDomainRuleList(allocator, &domains);

    if (object.get("domain")) |domain_value| {
        switch (domain_value) {
            .string => |domain| try appendDomainRule(allocator, &domains, domain),
            .array => |array| {
                for (array.items) |item| {
                    if (item != .string) return error.RuleDomainMustBeStringOrArray;
                    try appendDomainRule(allocator, &domains, item.string);
                }
            },
            else => return error.RuleDomainMustBeStringOrArray,
        }
    }

    var ips: std.ArrayList(IpRule) = .empty;
    errdefer ips.deinit(allocator);

    if (object.get("ip")) |ip_value| {
        switch (ip_value) {
            .string => |ip| try ips.append(allocator, try parseIpRule(ip)),
            .array => |array| {
                for (array.items) |item| {
                    if (item != .string) return error.RuleIpMustBeStringOrArray;
                    try ips.append(allocator, try parseIpRule(item.string));
                }
            },
            else => return error.RuleIpMustBeStringOrArray,
        }
    }

    const owned_inbound_tags = try inbound_tags.toOwnedSlice(allocator);
    errdefer {
        for (owned_inbound_tags) |tag| allocator.free(tag);
        allocator.free(owned_inbound_tags);
    }

    const owned_domains = try domains.toOwnedSlice(allocator);
    errdefer deinitDomainRuleSlice(allocator, owned_domains);

    const owned_ips = try ips.toOwnedSlice(allocator);
    errdefer allocator.free(owned_ips);

    return .{
        .inbound_tags = owned_inbound_tags,
        .domains = owned_domains,
        .ips = owned_ips,
        .outbound_tag = outbound_tag,
    };
}

fn parseIpRule(source: []const u8) !IpRule {
    const slash = std.mem.indexOfScalar(u8, source, '/');
    const address_text = if (slash) |index| source[0..index] else source;
    if (address_text.len == 0) return error.UnsupportedIpRule;

    const address = net.IpAddress.parse(address_text, 0) catch return error.UnsupportedIpRule;
    return switch (address) {
        .ip4 => |ip4| .{ .ip4 = .{
            .bytes = ip4.bytes,
            .prefix_len = try parsePrefixLen(source, slash, 32),
        } },
        .ip6 => |ip6| .{ .ip6 = .{
            .bytes = ip6.bytes,
            .prefix_len = try parsePrefixLen(source, slash, 128),
        } },
    };
}

fn parsePrefixLen(source: []const u8, slash: ?usize, max_prefix_len: u8) !u8 {
    const index = slash orelse return max_prefix_len;
    if (index + 1 >= source.len) return error.UnsupportedIpRule;
    const text = source[index + 1 ..];
    const value = std.fmt.parseInt(u16, text, 10) catch return error.UnsupportedIpRule;
    if (value > max_prefix_len) return error.UnsupportedIpRule;
    return @intCast(value);
}

fn appendString(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8), source: []const u8) !void {
    try list.append(allocator, try allocator.dupe(u8, source));
}

fn appendDomainRule(allocator: std.mem.Allocator, list: *std.ArrayList(DomainRule), source: []const u8) !void {
    try list.append(allocator, .{
        .pattern = try allocator.dupe(u8, source),
    });
}

fn requiredString(
    allocator: std.mem.Allocator,
    object: *const std.json.ObjectMap,
    key: []const u8,
    missing_error: anyerror,
) ![]const u8 {
    const value = object.get(key) orelse return missing_error;
    if (value != .string) return error.FieldMustBeString;
    return allocator.dupe(u8, value.string);
}

fn optionalString(
    allocator: std.mem.Allocator,
    object: *const std.json.ObjectMap,
    key: []const u8,
) !?[]const u8 {
    const value = object.get(key) orelse return null;
    if (value != .string) return error.FieldMustBeString;
    return try allocator.dupe(u8, value.string);
}

fn requiredPort(object: *const std.json.ObjectMap, key: []const u8, missing_error: anyerror) !u16 {
    const value = object.get(key) orelse return missing_error;
    return switch (value) {
        .integer => |port| parsePort(port),
        else => error.UnsupportedPortFormat,
    };
}

fn parsePort(port: i64) !u16 {
    if (port <= 0 or port > 65535) return error.InvalidPort;
    return @intCast(port);
}

fn stripDomainPrefix(pattern: []const u8) []const u8 {
    if (std.mem.startsWith(u8, pattern, "domain:")) return pattern["domain:".len..];
    return pattern;
}

fn deinitInboundList(allocator: std.mem.Allocator, list: *std.ArrayList(Inbound)) void {
    for (list.items) |*inbound| inbound.deinit(allocator);
    list.deinit(allocator);
}

fn deinitOutboundList(allocator: std.mem.Allocator, list: *std.ArrayList(Outbound)) void {
    for (list.items) |*outbound| outbound.deinit(allocator);
    list.deinit(allocator);
}

fn deinitRouteRuleList(allocator: std.mem.Allocator, list: *std.ArrayList(RouteRule)) void {
    for (list.items) |*rule| rule.deinit(allocator);
    list.deinit(allocator);
}

fn deinitDomainRuleList(allocator: std.mem.Allocator, list: *std.ArrayList(DomainRule)) void {
    for (list.items) |*domain| domain.deinit(allocator);
    list.deinit(allocator);
}

fn deinitStringList(allocator: std.mem.Allocator, list: *std.ArrayList([]const u8)) void {
    for (list.items) |item| allocator.free(item);
    list.deinit(allocator);
}

fn deinitDnsServerList(allocator: std.mem.Allocator, list: *std.ArrayList(DnsServer)) void {
    for (list.items) |*server| server.deinit(allocator);
    list.deinit(allocator);
}

fn deinitInboundSlice(allocator: std.mem.Allocator, inbounds: []Inbound) void {
    for (inbounds) |*inbound| inbound.deinit(allocator);
    allocator.free(inbounds);
}

fn deinitOutboundSlice(allocator: std.mem.Allocator, outbounds: []Outbound) void {
    for (outbounds) |*outbound| outbound.deinit(allocator);
    allocator.free(outbounds);
}

fn deinitRouteRuleSlice(allocator: std.mem.Allocator, rules: []RouteRule) void {
    for (rules) |*rule| rule.deinit(allocator);
    allocator.free(rules);
}

fn deinitDomainRuleSlice(allocator: std.mem.Allocator, domains: []DomainRule) void {
    for (domains) |*domain| domain.deinit(allocator);
    allocator.free(domains);
}

test "parses minimal xray-style config" {
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

    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectEqual(@as(usize, 1), cfg.inbounds.len);
    try std.testing.expectEqualStrings("socks-in", cfg.inbounds[0].tag.?);
    try std.testing.expectEqualStrings("127.0.0.1", cfg.inbounds[0].listen);
    try std.testing.expectEqual(@as(u16, 1080), cfg.inbounds[0].port);
    try std.testing.expectEqualStrings("socks", cfg.inbounds[0].protocol);
    try std.testing.expectEqual(@as(usize, 1), cfg.outbounds.len);
    try std.testing.expectEqualStrings("freedom", cfg.outbounds[0].protocol);
}

test "parses redirect reality subset" {
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
        \\          "fingerprint": "chrome"
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

    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectEqualStrings("redirect", cfg.inbounds[0].protocol);
    try std.testing.expectEqualStrings("proxy", cfg.defaultOutboundTag().?);
    try std.testing.expect(cfg.routing.rules[0].domains[0].matches("mail.google.com"));
    switch (cfg.outbounds[0].settings) {
        .vless => |vless| {
            try std.testing.expectEqualStrings("proxy.example.com", vless.address);
            try std.testing.expectEqualStrings("00000000-0000-0000-0000-000000000000", vless.id);
        },
        .none => return error.ExpectedVlessSettings,
    }
    try std.testing.expectEqualStrings("www.example.com", cfg.outbounds[0].stream.reality.?.server_name);
    try std.testing.expectEqual(tls_fingerprint.Fingerprint.chrome, cfg.outbounds[0].stream.reality.?.fingerprint);
}

test "defaults inbound listen address to loopback" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"port": 1080, "protocol": "socks"}
        \\  ]
        \\}
    ;

    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectEqualStrings("127.0.0.1", cfg.inbounds[0].listen);
}

test "parses dns config without enabling fakedns" {
    const source =
        \\{
        \\  "dns": {
        \\    "servers": [
        \\      {"resolver": "9.9.9.9", "outboundTag": "direct", "domains": ["domain:example.com"]},
        \\      {"resolver": "8.8.4.4", "outboundTag": "direct", "domains": ["domain:mail.example.com"]},
        \\      {"resolver": "77.88.8.8", "outboundTag": "direct", "domains": ["domain:ru"]},
        \\      {"resolver": "1.1.1.1:53", "outboundTag": "direct", "domains": ["domain:"]}
        \\    ]
        \\  },
        \\  "inbounds": [
        \\    {"tag": "dns-in", "listen": "127.0.0.1", "port": 1053, "protocol": "dns"}
        \\  ],
        \\  "outbounds": [
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ]
        \\}
    ;

    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectEqual(@as(usize, 4), cfg.dns.?.servers.len);
    try std.testing.expectEqualStrings("9.9.9.9", cfg.dns.?.selectServer("mail.example.com").resolver);
    try std.testing.expectEqualStrings("77.88.8.8", cfg.dns.?.selectServer("mail.ru").resolver);
    try std.testing.expectEqualStrings("1.1.1.1:53", cfg.dns.?.selectServer("other.net").resolver);
    try std.testing.expectEqualStrings("direct", cfg.dns.?.selectServer("other.net").outbound_tag);
    try std.testing.expect(cfg.dns.?.fake_dns == null);
}

test "parses explicit fakedns with defaults" {
    const source =
        \\{
        \\  "dns": {
        \\    "servers": [
        \\      {"resolver": "1.1.1.1", "outboundTag": "direct", "domains": ["domain:"]}
        \\    ],
        \\    "fakeDns": {}
        \\  }
        \\}
    ;

    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    const fake_dns = cfg.dns.?.fake_dns.?;
    try std.testing.expectEqualStrings("198.18.0.0/15", fake_dns.ip_pool);
    try std.testing.expectEqualStrings("fc00::/18", fake_dns.ip_pool6);
    try std.testing.expectEqual(@as(u32, 60), fake_dns.ttl);
}

test "rejects dns config without final fallback resolver" {
    const source =
        \\{
        \\  "dns": {
        \\    "servers": [
        \\      {"resolver": "1.1.1.1", "outboundTag": "direct", "domains": ["domain:example.com"]}
        \\    ]
        \\  }
        \\}
    ;

    try std.testing.expectError(error.MissingDnsFallbackServer, parse(std.testing.allocator, source));
}

test "rejects dns server without outbound tag" {
    const source =
        \\{
        \\  "dns": {
        \\    "servers": [
        \\      {"resolver": "1.1.1.1", "domains": ["domain:"]}
        \\    ]
        \\  }
        \\}
    ;

    try std.testing.expectError(error.MissingDnsOutboundTag, parse(std.testing.allocator, source));
}

test "parses route IP CIDR rules" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ],
        \\  "routing": {
        \\    "defaultOutboundTag": "direct",
        \\    "rules": [
        \\      {"ip": ["127.0.0.0/8", "2001:db8::/32", "8.8.8.8"], "outboundTag": "direct"}
        \\    ]
        \\  }
        \\}
    ;

    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectEqual(@as(usize, 3), cfg.routing.rules[0].ips.len);
    try std.testing.expect(cfg.routing.rules[0].ips[0].matches(try net.IpAddress.parse("127.0.0.1", 80)));
    try std.testing.expect(cfg.routing.rules[0].ips[1].matches(try net.IpAddress.parse("2001:db8::1", 80)));
    try std.testing.expect(cfg.routing.rules[0].ips[2].matches(try net.IpAddress.parse("8.8.8.8", 53)));
}

test "rejects unsupported route IP rules" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"tag": "socks-in", "listen": "127.0.0.1", "port": 1080, "protocol": "socks"}
        \\  ],
        \\  "outbounds": [
        \\    {"tag": "direct", "protocol": "freedom"}
        \\  ],
        \\  "routing": {
        \\    "defaultOutboundTag": "direct",
        \\    "rules": [
        \\      {"ip": ["geoip:private"], "outboundTag": "direct"}
        \\    ]
        \\  }
        \\}
    ;

    try std.testing.expectError(error.UnsupportedIpRule, parse(std.testing.allocator, source));
}

test "defaults Reality fingerprint to Firefox" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"port": 1080, "protocol": "socks"}
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
        \\          "shortId": "0123456789abcdef"
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    var cfg = try parse(std.testing.allocator, source);
    defer cfg.deinit();

    try std.testing.expectEqual(tls_fingerprint.Fingerprint.firefox, cfg.outbounds[0].stream.reality.?.fingerprint);
    try std.testing.expectEqual(tls_cipher_policy.CipherPolicy.firefox, cfg.outbounds[0].stream.reality.?.cipher_policy);
}

test "parses explicit Reality cipher policy" {
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{
        \\  "serverName": "www.example.com",
        \\  "publicKey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        \\  "shortId": "0123456789abcdef",
        \\  "cipherPolicy": "chacha20-only"
        \\}
    , .{});
    defer parsed.deinit();

    var settings = try parseRealitySettings(std.testing.allocator, parsed.value);
    defer settings.deinit(std.testing.allocator);
    try std.testing.expectEqual(tls_cipher_policy.CipherPolicy.chacha20_only, settings.cipher_policy);
}

test "rejects unsupported Reality fingerprints" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"port": 1080, "protocol": "socks"}
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
        \\          "fingerprint": "unsafe"
        \\        }
        \\      }
        \\    }
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.UnsupportedTlsFingerprint, parse(std.testing.allocator, source));
}

test "rejects invalid inbound ports" {
    const source =
        \\{
        \\  "inbounds": [
        \\    {"listen": "127.0.0.1", "port": 70000, "protocol": "socks"}
        \\  ]
        \\}
    ;

    try std.testing.expectError(error.InvalidPort, parse(std.testing.allocator, source));
}
