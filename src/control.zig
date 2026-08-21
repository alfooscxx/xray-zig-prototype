const std = @import("std");
const Io = std.Io;
const net = Io.net;

const monitoring = @import("monitoring.zig");

pub const default_socket_path = "/run/xray-zig/control.sock";
pub const max_request_bytes = 256;
pub const max_response_bytes = 64 * 1024;

pub const Server = struct {
    path: []const u8,
    dataplane: []const u8,
    version: []const u8,
    refresh_context: ?*anyopaque = null,
    refresh_fn: ?*const fn (*anyopaque) void = null,

    pub fn run(self: Server, io: Io) !void {
        if (!std.fs.path.isAbsolute(self.path)) return error.InvalidControlSocketPath;
        const parent = std.fs.path.dirname(self.path) orelse return error.InvalidControlSocketPath;
        _ = try Io.Dir.cwd().createDirPathStatus(io, parent, .fromMode(0o700));
        var address = try net.UnixAddress.init(self.path);
        const existing = Io.Dir.cwd().statFile(io, self.path, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => null,
            else => return err,
        };
        if (existing) |stat| {
            if (stat.kind != .unix_domain_socket) return error.UnsafeControlSocketPath;
            if (address.connect(io)) |stream| {
                stream.close(io);
                return error.ControlSocketInUse;
            } else |_| {
                try Io.Dir.deleteFileAbsolute(io, self.path);
            }
        }
        defer Io.Dir.deleteFileAbsolute(io, self.path) catch {};

        var listener = try address.listen(io, .{ .kernel_backlog = 8 });
        defer listener.deinit(io);
        try Io.Dir.cwd().setFilePermissions(io, self.path, .fromMode(0o600), .{});
        monitoring.registry.control_up.store(true, .release);
        defer monitoring.registry.control_up.store(false, .release);

        var group: Io.Group = .init;
        defer group.cancel(io);
        while (true) {
            const stream = listener.accept(io) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                else => |other| return other,
            };
            group.concurrent(io, handleConnection, .{ self, stream, io }) catch {
                stream.close(io);
                continue;
            };
        }
    }
};

fn handleConnection(server: Server, stream: net.Stream, io: Io) Io.Cancelable!void {
    defer stream.close(io);
    var read_buffer: [max_request_bytes]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    const request = reader.interface.takeDelimiter('\n') catch {
        sendError(stream, io, "request_too_large") catch {};
        return;
    } orelse return;
    if (server.refresh_fn) |refresh| refresh(server.refresh_context.?);

    var write_buffer: [4096]u8 = undefined;
    var socket_writer = stream.writer(io, &write_buffer);
    const writer = &socket_writer.interface;
    serve(server, request, writer, nowNs(io)) catch {
        sendWriterError(writer, "response_failed") catch {};
    };
    writer.flush() catch {};
}
pub fn serve(server: Server, request: []const u8, writer: *Io.Writer, now_ns: u64) !void {
    var words = std.mem.tokenizeScalar(u8, request, ' ');
    const operation = words.next() orelse return sendWriterError(writer, "empty_request");
    if (std.mem.eql(u8, operation, "status") or std.mem.eql(u8, operation, "top")) {
        if (words.next() != null) return sendWriterError(writer, "unknown_field");
        return monitoring.registry.renderStatus(writer, now_ns, server.dataplane, server.version);
    }
    if (std.mem.eql(u8, operation, "metrics")) {
        if (words.next() != null) return sendWriterError(writer, "unknown_field");
        return monitoring.registry.renderMetrics(writer, now_ns, server.dataplane, server.version);
    }
    if (std.mem.eql(u8, operation, "bpf") or std.mem.eql(u8, operation, "bpf-status")) {
        if (words.next() != null) return sendWriterError(writer, "unknown_field");
        return monitoring.registry.renderBpfStatus(writer);
    }
    if (std.mem.eql(u8, operation, "events") or std.mem.eql(u8, operation, "recent-events")) {
        var limit: usize = 50;
        if (words.next()) |limit_text| {
            limit = std.fmt.parseUnsigned(usize, limit_text, 10) catch return sendWriterError(writer, "invalid_limit");
        }
        if (words.next() != null or limit > monitoring.event_capacity) return sendWriterError(writer, "invalid_limit");
        return monitoring.registry.renderEvents(writer, limit);
    }
    return sendWriterError(writer, "unknown_operation");
}

pub fn runClient(io: Io, path: []const u8, request: []const u8, output: *Io.Writer) !void {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidControlSocketPath;
    if (request.len + 1 > max_request_bytes) return error.ControlRequestTooLarge;
    var address = try net.UnixAddress.init(path);
    const stream = try address.connect(io);
    defer stream.close(io);

    var write_buffer: [512]u8 = undefined;
    var writer = stream.writer(io, &write_buffer);
    try writer.interface.writeAll(request);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
    try stream.shutdown(io, .send);

    var read_buffer: [4096]u8 = undefined;
    var reader = stream.reader(io, &read_buffer);
    var total: usize = 0;
    while (true) {
        var chunk: [4096]u8 = undefined;
        const len = try reader.interface.readSliceShort(&chunk);
        if (len == 0) break;
        total += len;
        if (total > max_response_bytes) return error.ControlResponseTooLarge;
        try output.writeAll(chunk[0..len]);
    }
}

fn sendError(stream: net.Stream, io: Io, reason: []const u8) !void {
    var buffer: [256]u8 = undefined;
    var writer = stream.writer(io, &buffer);
    try sendWriterError(&writer.interface, reason);
    try writer.interface.flush();
}

fn sendWriterError(writer: *Io.Writer, reason: []const u8) !void {
    try writer.print("{{\"error\":\"{s}\"}}\n", .{reason});
}

pub fn nowNs(io: Io) u64 {
    const value = Io.Timestamp.now(io, .awake).nanoseconds;
    return if (value > 0) @intCast(value) else 0;
}

test "control protocol rejects fields and bounds event limit" {
    var buffer: [1024]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    const server: Server = .{ .path = "/tmp/unused", .dataplane = "redirect", .version = "test" };
    try serve(server, "status extra", &writer, 0);
    try std.testing.expectEqualStrings("{\"error\":\"unknown_field\"}\n", writer.buffered());

    writer = .fixed(&buffer);
    try serve(server, "events 65", &writer, 0);
    try std.testing.expectEqualStrings("{\"error\":\"invalid_limit\"}\n", writer.buffered());
}
