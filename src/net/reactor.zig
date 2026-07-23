const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;

const linux = std.os.linux;
const posix = std.posix;

const max_connections = 256;
const buffer_size = 16 * 1024;
const poll_timeout_ms = 20;

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
    next: ?*Connection = null,
};

pub const Reactor = struct {
    allocator: std.mem.Allocator,
    io: Io,
    pending_mutex: std.atomic.Mutex = .unlocked,
    pending_head: ?*Connection = null,
    pending_tail: ?*Connection = null,
    active_count: usize = 0,

    pub fn init(allocator: std.mem.Allocator, io: Io) Reactor {
        return .{ .allocator = allocator, .io = io };
    }

    pub fn adoptDuplicate(self: *Reactor, client: net.Stream, upstream: net.Stream) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;

        const client_copy = try duplicateStream(client);
        errdefer client_copy.close(self.io);
        const upstream_copy = try duplicateStream(upstream);
        errdefer upstream_copy.close(self.io);

        try setNonBlocking(client_copy.socket.handle);
        try setNonBlocking(upstream_copy.socket.handle);

        const connection = try self.allocator.create(Connection);
        connection.* = .{ .client = client_copy, .upstream = upstream_copy };

        lock(&self.pending_mutex);
        defer self.pending_mutex.unlock();
        if (self.pending_tail) |tail| {
            tail.next = connection;
        } else {
            self.pending_head = connection;
        }
        self.pending_tail = connection;
    }

    pub fn run(self: *Reactor) Io.Cancelable!void {
        var active_head: ?*Connection = null;
        var poll_fds: [max_connections * 2]posix.pollfd = undefined;
        var poll_connections: [max_connections]*Connection = undefined;

        while (true) {
            self.takePending(&active_head);

            var count: usize = 0;
            var current = active_head;
            while (current) |connection| : (current = connection.next) {
                if (count == max_connections) break;
                poll_connections[count] = connection;
                poll_fds[count * 2] = .{
                    .fd = connection.client.socket.handle,
                    .events = readEvents(connection.client_eof, &connection.client_to_upstream) |
                        writeEvents(&connection.upstream_to_client),
                    .revents = 0,
                };
                poll_fds[count * 2 + 1] = .{
                    .fd = connection.upstream.socket.handle,
                    .events = readEvents(connection.upstream_eof, &connection.upstream_to_client) |
                        writeEvents(&connection.client_to_upstream),
                    .revents = 0,
                };
                count += 1;
            }

            _ = posix.poll(poll_fds[0 .. count * 2], poll_timeout_ms) catch continue;

            var index: usize = 0;
            while (index < count) : (index += 1) {
                const connection = poll_connections[index];
                const client_events = poll_fds[index * 2].revents;
                const upstream_events = poll_fds[index * 2 + 1].revents;
                service(connection, client_events, upstream_events);
            }

            var link = &active_head;
            while (link.*) |connection| {
                if (finished(connection)) {
                    link.* = connection.next;
                    self.closeConnection(connection);
                } else {
                    link = &connection.next;
                }
            }
        }
    }

    fn takePending(self: *Reactor, active_head: *?*Connection) void {
        lock(&self.pending_mutex);
        defer self.pending_mutex.unlock();

        var pending = self.pending_head;
        self.pending_head = null;
        self.pending_tail = null;
        while (pending) |connection| {
            const next = connection.next;
            if (self.active_count >= max_connections) {
                self.closePending(connection);
            } else {
                connection.next = active_head.*;
                active_head.* = connection;
                self.active_count += 1;
            }
            pending = next;
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
};

fn readEvents(eof: bool, buffer: *const Buffer) i16 {
    return if (!eof and buffer.empty()) posix.POLL.IN else 0;
}

fn writeEvents(buffer: *const Buffer) i16 {
    return if (!buffer.empty()) posix.POLL.OUT else 0;
}

fn service(connection: *Connection, client_events: i16, upstream_events: i16) void {
    const terminal = posix.POLL.ERR | posix.POLL.NVAL;
    if (client_events & terminal != 0 or upstream_events & terminal != 0) {
        connection.failed = true;
        return;
    }

    if (client_events & (posix.POLL.IN | posix.POLL.HUP) != 0 and connection.client_to_upstream.empty()) {
        readSocket(connection.client.socket.handle, &connection.client_to_upstream, &connection.client_eof, &connection.failed);
    }
    if (upstream_events & posix.POLL.OUT != 0 and !connection.client_to_upstream.empty()) {
        writeSocket(connection.upstream.socket.handle, &connection.client_to_upstream, &connection.failed);
    }
    if (connection.client_eof and connection.client_to_upstream.empty() and !connection.upstream_send_shutdown) {
        shutdownSend(connection.upstream.socket.handle);
        connection.upstream_send_shutdown = true;
    }

    if (upstream_events & (posix.POLL.IN | posix.POLL.HUP) != 0 and connection.upstream_to_client.empty()) {
        readSocket(connection.upstream.socket.handle, &connection.upstream_to_client, &connection.upstream_eof, &connection.failed);
    }
    if (client_events & posix.POLL.OUT != 0 and !connection.upstream_to_client.empty()) {
        writeSocket(connection.client.socket.handle, &connection.upstream_to_client, &connection.failed);
    }
    if (connection.upstream_eof and connection.upstream_to_client.empty() and !connection.client_send_shutdown) {
        shutdownSend(connection.client.socket.handle);
        connection.client_send_shutdown = true;
    }
}

fn finished(connection: *const Connection) bool {
    return connection.failed or connection.client_eof and connection.upstream_eof and
        connection.client_to_upstream.empty() and connection.upstream_to_client.empty();
}

fn readSocket(fd: posix.fd_t, buffer: *Buffer, eof: *bool, failed: *bool) void {
    const rc = linux.read(fd, &buffer.bytes, buffer.bytes.len);
    switch (linux.errno(rc)) {
        .SUCCESS => {
            const n: usize = @intCast(rc);
            if (n == 0) {
                eof.* = true;
            } else {
                buffer.start = 0;
                buffer.end = n;
            }
        },
        .AGAIN, .INTR => {},
        else => failed.* = true,
    }
}

fn writeSocket(fd: posix.fd_t, buffer: *Buffer, failed: *bool) void {
    const bytes = buffer.readable();
    const rc = linux.write(fd, bytes.ptr, bytes.len);
    switch (linux.errno(rc)) {
        .SUCCESS => {
            buffer.start += @intCast(rc);
            if (buffer.empty()) buffer.reset();
        },
        .AGAIN, .INTR => {},
        else => failed.* = true,
    }
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

fn lock(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}
