const Io = @import("std").Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const dns_upstream = @import("../../dns/upstream.zig");
const session = @import("../../net/session.zig");

pub const Error = error{
    MissingDnsConfig,
    MissingDnsUpstream,
    UnsupportedDnsUpstream,
};

pub fn handle(
    client: net.Stream,
    sess: session.Session,
    preface: session.Preface,
    dns_config: ?config.DnsConfig,
    io: Io,
) !void {
    const cfg = dns_config orelse return error.MissingDnsConfig;
    if (cfg.servers.len == 0) return error.MissingDnsUpstream;

    const domain = domainFromSession(sess);
    const server = cfg.selectServer(domain);
    var upstream_address = dns_upstream.parseAddress(server.resolver) catch return error.UnsupportedDnsUpstream;
    const upstream = try upstream_address.connect(io, .{
        .mode = .stream,
        .protocol = .tcp,
    });
    defer upstream.close(io);

    var write_buffer: [4096]u8 = undefined;
    var writer = upstream.writer(io, &write_buffer);
    try session.writePreface(&writer.interface, preface);
    try session.bridge(client, upstream, io);
}

fn domainFromSession(sess: session.Session) []const u8 {
    if (sess.sniffed_domain) |domain| return domain;
    return switch (sess.target) {
        .host => |host| host.name.bytes,
        .address => "",
    };
}
