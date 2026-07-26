const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const dns_client = @import("../../dns/client.zig");
const session = @import("../../net/session.zig");

pub fn handle(
    client: net.Stream,
    sess: session.Session,
    preface: session.Preface,
    dns_config: ?config.DnsConfig,
    dispatcher: session.Dispatcher,
    raw_reactor: *session.RawReactor,
    io: Io,
) !void {
    const upstream = switch (sess.target) {
        .address => try session.connectTarget(sess.target, io),
        .host => |host| if (dns_config) |cfg|
            try dns_client.connect(host, sess.preferred_family, cfg, dispatcher, io)
        else
            try session.connectTarget(sess.target, io),
    };
    defer upstream.close(io);

    var write_buffer: [4096]u8 = undefined;
    var writer = upstream.writer(io, &write_buffer);
    try session.writePreface(&writer.interface, preface);
    try raw_reactor.adoptDuplicate(client, upstream);
}
