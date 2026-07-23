const std = @import("std");
const Io = std.Io;
const net = Io.net;

const session = @import("../../net/session.zig");

pub fn handle(client: net.Stream, sess: session.Session, preface: session.Preface, raw_reactor: *session.RawReactor, io: Io) !void {
    const upstream = try session.connectTarget(sess.target, io);
    defer upstream.close(io);

    var write_buffer: [4096]u8 = undefined;
    var writer = upstream.writer(io, &write_buffer);
    try session.writePreface(&writer.interface, preface);
    try raw_reactor.adoptDuplicate(client, upstream);
}
