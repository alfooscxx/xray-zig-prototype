const Io = @import("std").Io;
const net = Io.net;

const session = @import("../../net/session.zig");

pub fn handle(client: net.Stream, sess: session.Session, preface: session.Preface, io: Io) !void {
    _ = sess;
    _ = preface;
    client.shutdown(io, .both) catch {};
}
