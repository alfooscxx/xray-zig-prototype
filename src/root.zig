pub const version = "0.0.7";

pub const config = @import("config/mod.zig");
pub const core = @import("core/mod.zig");
pub const dns = struct {
    pub const client = @import("dns/client.zig");
    pub const fakedns = @import("dns/fakedns.zig");
    pub const protocol = @import("dns/protocol.zig");
    pub const upstream = @import("dns/upstream.zig");
};
pub const net = struct {
    pub const session = @import("net/session.zig");
    pub const sniff = @import("net/sniff.zig");
};
pub const proxy = struct {
    pub const blackhole = @import("proxy/blackhole/outbound.zig");
    pub const dns = struct {
        pub const inbound = @import("proxy/dns/inbound.zig");
        pub const outbound = @import("proxy/dns/outbound.zig");
    };
    pub const freedom = @import("proxy/freedom/outbound.zig");
    pub const redirect = @import("proxy/redirect/inbound.zig");
    pub const socks = @import("proxy/socks/inbound.zig");
    pub const vless = @import("proxy/vless/outbound.zig");
};
pub const routing = @import("routing/mod.zig");
pub const transport = struct {
    pub const reality = @import("transport/reality/client.zig");
    pub const tls = struct {
        pub const client_hello = @import("transport/tls/client_hello.zig");
        pub const fingerprint = @import("transport/tls/fingerprint.zig");
    };
};

test {
    _ = config;
    _ = core;
    _ = dns.client;
    _ = dns.fakedns;
    _ = dns.protocol;
    _ = dns.upstream;
    _ = net.session;
    _ = net.sniff;
    _ = proxy.blackhole;
    _ = proxy.dns.inbound;
    _ = proxy.dns.outbound;
    _ = proxy.freedom;
    _ = proxy.redirect;
    _ = proxy.socks;
    _ = proxy.vless;
    _ = routing;
    _ = transport.reality;
    _ = transport.tls.client_hello;
    _ = transport.tls.fingerprint;
}
