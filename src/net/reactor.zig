const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;

const linux = std.os.linux;
const posix = std.posix;
const diagnostics = @import("../diagnostics.zig");

const buffer_size = 16 * 1024;
const cancellation_poll_ms = 1000;
const connection_idle_timeout_ns = 300 * std.time.ns_per_s;

const Buffer = struct {
    bytes: [buffer_size]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    fn empty(self: *const Buffer) bool {
        return self.start == self.end;
    }

    fn readable(self: *Buffer) []u8 {
        return self.bytes[self.start..self.end];
    }

    fn reset(self: *Buffer) void {
        self.start = 0;
        self.end = 0;
    }
};

const Connection = struct {
    client: net.Stream,
    upstream: net.Stream,
    client_to_upstream: Buffer = .{},
    upstream_to_client: Buffer = .{},
    client_eof: bool = false,
    upstream_eof: bool = false,
    upstream_send_shutdown: bool = false,
    client_send_shutdown: bool = false,
    failed: bool = false,
    last_activity: Io.Timestamp,
    next: ?*Connection = null,
};

pub const Reactor = struct {
    allocator: std.mem.Allocator,
    io: Io,
    wake_fd: posix.fd_t,
    max_connections: usize,
    poll_fds: []posix.pollfd,
    poll_connections: []*Connection,
    pending_head: std.atomic.Value(?*Connection) = .init(null),
    stopped: std.atomic.Value(bool) = .init(false),
    active_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, io: Io, max_connections: usize) !Reactor {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
        if (max_connections == 0 or
            max_connections > (std.math.maxInt(usize) - 1) / 2)
        {
            return error.InvalidReactorCapacity;
        }

        const poll_fds = try allocator.alloc(posix.pollfd, max_connections * 2 + 1);
        errdefer allocator.free(poll_fds);
        const poll_connections = try allocator.alloc(*Connection, max_connections);
        errdefer allocator.free(poll_connections);

        const rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
        return switch (linux.errno(rc)) {
            .SUCCESS => .{
                .allocator = allocator,
                .io = io,
                .wake_fd = @intCast(rc),
                .max_connections = max_connections,
                .poll_fds = poll_fds,
                .poll_connections = poll_connections,
            },
            .MFILE, .NFILE, .NOMEM => error.SystemResources,
            else => error.Unexpected,
        };
    }

    pub fn deinit(self: *Reactor) void {
        self.stop();
        self.closePendingList(self.pending_head.swap(null, .acquire));
        _ = linux.close(self.wake_fd);
        self.allocator.free(self.poll_connections);
        self.allocator.free(self.poll_fds);
        self.* = undefined;
    }

    pub fn stop(self: *Reactor) void {
        if (self.stopped.swap(true, .release)) return;
        self.wake();
    }

    pub fn adoptDuplicate(self: *Reactor, client: net.Stream, upstream: net.Stream) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
        if (self.stopped.load(.acquire)) return error.ReactorStopped;

        const client_copy = try duplicateStream(client);
        errdefer client_copy.close(self.io);
        const upstream_copy = try duplicateStream(upstream);
        errdefer upstream_copy.close(self.io);

        try setNonBlocking(client_copy.socket.handle);
        try setNonBlocking(upstream_copy.socket.handle);

        const connection = try self.allocator.create(Connection);
        connection.* = .{
            .client = client_copy,
            .upstream = upstream_copy,
            .last_activity = Io.Timestamp.now(self.io, .awake),
        };

        self.pushPending(connection);
        self.wake();
    }

    fn pushPending(self: *Reactor, connection: *Connection) void {
        var head = self.pending_head.load(.monotonic);
        while (true) {
            connection.next = head;
            head = self.pending_head.cmpxchgWeak(
                head,
                connection,
                .release,
                .monotonic,
            ) orelse return;
        }
    }

    pub fn run(self: *Reactor) Io.Cancelable!void {
        var active_head: ?*Connection = null;
        defer {
            self.closeActiveList(active_head);
            self.closePendingList(self.pending_head.swap(null, .acquire));
        }

        while (true) {
            self.takePending(&active_head);
            diagnostics.setRawReactorCount(self.active_count);
            if (self.stopped.load(.acquire)) return;

            self.poll_fds[0] = .{
                .fd = self.wake_fd,
                .events = posix.POLL.IN,
                .revents = 0,
            };

            var count: usize = 0;
            var current = active_head;
            while (current) |connection| : (current = connection.next) {
                if (count == self.max_connections) break;
                self.poll_connections[count] = connection;
                self.poll_fds[count * 2 + 1] = .{
                    .fd = connection.client.socket.handle,
                    .events = readEvents(connection.client_eof, &connection.client_to_upstream) |
                        writeEvents(&connection.upstream_to_client),
                    .revents = 0,
                };
                self.poll_fds[count * 2 + 2] = .{
                    .fd = connection.upstream.socket.handle,
                    .events = readEvents(connection.upstream_eof, &connection.upstream_to_client) |
                        writeEvents(&connection.client_to_upstream),
                    .revents = 0,
                };
                count += 1;
            }

            _ = posix.poll(self.poll_fds[0 .. count * 2 + 1], cancellation_poll_ms) catch continue;
            try Io.checkCancel(self.io);
            if (self.poll_fds[0].revents & posix.POLL.IN != 0) self.drainWake();
            if (self.poll_fds[0].revents & (posix.POLL.ERR | posix.POLL.HUP | posix.POLL.NVAL) != 0) return;
            if (self.stopped.load(.acquire)) return;

            const now = Io.Timestamp.now(self.io, .awake);
            var index: usize = 0;
            while (index < count) : (index += 1) {
                const connection = self.poll_connections[index];
                const client_events = self.poll_fds[index * 2 + 1].revents;
                const upstream_events = self.poll_fds[index * 2 + 2].revents;
                if (service(connection, client_events, upstream_events)) {
                    connection.last_activity = now;
                }
            }

            var link = &active_head;
            while (link.*) |connection| {
                if (finished(connection) or idleExpired(connection, now)) {
                    link.* = connection.next;
                    self.closeConnection(connection);
                } else {
                    link = &connection.next;
                }
            }
            diagnostics.setRawReactorCount(self.active_count);
        }
    }

    fn takePending(self: *Reactor, active_head: *?*Connection) void {
        var pending = self.pending_head.swap(null, .acquire);
        while (pending) |connection| {
            const next = connection.next;
            if (self.active_count >= self.max_connections) {
                self.closePending(connection);
            } else {
                connection.next = active_head.*;
                active_head.* = connection;
                self.active_count += 1;
            }
            pending = next;
        }
    }

    fn closeActiveList(self: *Reactor, head: ?*Connection) void {
        var current = head;
        while (current) |connection| {
            const next = connection.next;
            self.closeConnection(connection);
            current = next;
        }
    }

    fn closePendingList(self: *Reactor, head: ?*Connection) void {
        var current = head;
        while (current) |connection| {
            const next = connection.next;
            self.closePending(connection);
            current = next;
        }
    }

    fn closeConnection(self: *Reactor, connection: *Connection) void {
        connection.client.close(self.io);
        connection.upstream.close(self.io);
        self.allocator.destroy(connection);
        if (self.active_count > 0) self.active_count -= 1;
    }

    fn closePending(self: *Reactor, connection: *Connection) void {
        connection.client.close(self.io);
        connection.upstream.close(self.io);
        self.allocator.destroy(connection);
    }

    fn wake(self: *Reactor) void {
        var value: u64 = 1;
        while (true) {
            const rc = linux.write(self.wake_fd, @ptrCast(&value), @sizeOf(u64));
            switch (linux.errno(rc)) {
                .SUCCESS, .AGAIN => return,
                .INTR => continue,
                else => return,
            }
        }
    }

    fn drainWake(self: *Reactor) void {
        var value: u64 = undefined;
        while (true) {
            const rc = linux.read(self.wake_fd, @ptrCast(&value), @sizeOf(u64));
            switch (linux.errno(rc)) {
                .SUCCESS, .AGAIN => return,
                .INTR => continue,
                else => return,
            }
        }
    }
};

fn readEvents(eof: bool, buffer: *const Buffer) i16 {
    return if (!eof and buffer.empty()) posix.POLL.IN else 0;
}

fn writeEvents(buffer: *const Buffer) i16 {
    return if (!buffer.empty()) posix.POLL.OUT else 0;
}

fn service(connection: *Connection, client_events: i16, upstream_events: i16) bool {
    const terminal = posix.POLL.ERR | posix.POLL.NVAL;
    if (client_events & terminal != 0 or upstream_events & terminal != 0) {
        connection.failed = true;
        return false;
    }

    var activity = false;
    if (client_events & (posix.POLL.IN | posix.POLL.HUP) != 0 and connection.client_to_upstream.empty()) {
        activity = readSocket(connection.client.socket.handle, &connection.client_to_upstream, &connection.client_eof, &connection.failed) or activity;
    }
    if (upstream_events & posix.POLL.OUT != 0 and !connection.client_to_upstream.empty()) {
        activity = writeSocket(connection.upstream.socket.handle, &connection.client_to_upstream, &connection.failed) or activity;
    }
    if (connection.client_eof and connection.client_to_upstream.empty() and !connection.upstream_send_shutdown) {
        shutdownSend(connection.upstream.socket.handle);
        connection.upstream_send_shutdown = true;
    }

    if (upstream_events & (posix.POLL.IN | posix.POLL.HUP) != 0 and connection.upstream_to_client.empty()) {
        activity = readSocket(connection.upstream.socket.handle, &connection.upstream_to_client, &connection.upstream_eof, &connection.failed) or activity;
    }
    if (client_events & posix.POLL.OUT != 0 and !connection.upstream_to_client.empty()) {
        activity = writeSocket(connection.client.socket.handle, &connection.upstream_to_client, &connection.failed) or activity;
    }
    if (connection.upstream_eof and connection.upstream_to_client.empty() and !connection.client_send_shutdown) {
        shutdownSend(connection.client.socket.handle);
        connection.client_send_shutdown = true;
    }
    return activity;
}

fn finished(connection: *const Connection) bool {
    return connection.failed or connection.client_eof and connection.upstream_eof and
        connection.client_to_upstream.empty() and connection.upstream_to_client.empty();
}

fn idleExpired(connection: *const Connection, now: Io.Timestamp) bool {
    return now.nanoseconds - connection.last_activity.nanoseconds >= connection_idle_timeout_ns;
}

fn readSocket(fd: posix.fd_t, buffer: *Buffer, eof: *bool, failed: *bool) bool {
    const rc = linux.read(fd, &buffer.bytes, buffer.bytes.len);
    return switch (linux.errno(rc)) {
        .SUCCESS => {
            const n: usize = @intCast(rc);
            if (n == 0) {
                eof.* = true;
            } else {
                buffer.start = 0;
                buffer.end = n;
            }
            return n != 0;
        },
        .AGAIN, .INTR => false,
        else => {
            failed.* = true;
            return false;
        },
    };
}

fn writeSocket(fd: posix.fd_t, buffer: *Buffer, failed: *bool) bool {
    const bytes = buffer.readable();
    const rc = linux.write(fd, bytes.ptr, bytes.len);
    return switch (linux.errno(rc)) {
        .SUCCESS => {
            const n: usize = @intCast(rc);
            buffer.start += n;
            if (buffer.empty()) buffer.reset();
            return n != 0;
        },
        .AGAIN, .INTR => false,
        else => {
            failed.* = true;
            return false;
        },
    };
}

fn shutdownSend(fd: posix.fd_t) void {
    _ = linux.shutdown(fd, linux.SHUT.WR);
}

fn duplicateStream(stream: net.Stream) !net.Stream {
    const rc = linux.dup(stream.socket.handle);
    if (linux.errno(rc) != .SUCCESS) return error.SystemResources;
    return .{ .socket = .{
        .handle = @intCast(rc),
        .address = stream.socket.address,
    } };
}

fn setNonBlocking(fd: posix.fd_t) !void {
    const get_rc = posix.system.fcntl(fd, posix.F.GETFL, @as(usize, 0));
    if (posix.errno(get_rc) != .SUCCESS) return error.Unexpected;
    const nonblock = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    const set_rc = posix.system.fcntl(fd, posix.F.SETFL, get_rc | nonblock);
    if (posix.errno(set_rc) != .SUCCESS) return error.Unexpected;
}

test "pending connections use a lock-free handoff stack" {
    var reactor: Reactor = .{
        .allocator = std.testing.allocator,
        .io = std.Io.failing,
        .wake_fd = -1,
        .max_connections = 2,
        .poll_fds = undefined,
        .poll_connections = undefined,
    };
    var first: Connection = .{ .client = undefined, .upstream = undefined, .last_activity = .zero };
    var second: Connection = .{ .client = undefined, .upstream = undefined, .last_activity = .zero };

    reactor.pushPending(&first);
    reactor.pushPending(&second);

    const head = reactor.pending_head.swap(null, .acquire).?;
    try std.testing.expectEqual(&second, head);
    try std.testing.expectEqual(&first, head.next.?);
    try std.testing.expect(head.next.?.next == null);
}

test "raw connection idle timeout uses monotonic activity" {
    const connection: Connection = .{
        .client = undefined,
        .upstream = undefined,
        .last_activity = .fromNanoseconds(10),
    };

    try std.testing.expect(!idleExpired(
        &connection,
        .fromNanoseconds(10 + connection_idle_timeout_ns - 1),
    ));
    try std.testing.expect(idleExpired(
        &connection,
        .fromNanoseconds(10 + connection_idle_timeout_ns),
    ));
}
