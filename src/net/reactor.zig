const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;

const linux = std.os.linux;
const posix = std.posix;
const diagnostics = @import("../diagnostics.zig");

const buffer_size = 16 * 1024;
const connection_idle_timeout_ns = 300 * std.time.ns_per_s;
const timer_poll_ms = 1000;
pub const max_connections_per_ring = 4095;
const maximum_ring_entries: usize = 32768;

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
    cleanup: ?Cleanup = null,
    client_recv_pending: bool = false,
    upstream_recv_pending: bool = false,
    client_send_pending: bool = false,
    upstream_send_pending: bool = false,
    cancellation_requested: bool = false,
    last_activity: Io.Timestamp,
    next: ?*Connection = null,
};

pub const Cleanup = struct {
    context: *anyopaque,
    callback: *const fn (*anyopaque) void,
    health_callback: ?*const fn (*anyopaque) bool = null,

    fn run(self: Cleanup) void {
        self.callback(self.context);
    }

    fn healthy(self: Cleanup) bool {
        return if (self.health_callback) |callback| callback(self.context) else true;
    }
};

pub const Reactor = struct {
    allocator: std.mem.Allocator,
    io: Io,
    wake_fd: posix.fd_t,
    max_connections: usize,
    ring: linux.IoUring,
    ring_live: bool = true,
    completions: []linux.io_uring_cqe,
    pending_head: std.atomic.Value(?*Connection) = .init(null),
    admission_mutex: std.atomic.Mutex = .unlocked,
    stopped: std.atomic.Value(bool) = .init(false),
    active_count: usize = 0,
    wake_value: u64 = 0,
    wake_pending: bool = false,
    timer_spec: linux.kernel_timespec = .{
        .sec = 0,
        .nsec = timer_poll_ms * std.time.ns_per_ms,
    },
    timer_pending: bool = false,

    const wake_user_data: u64 = 1;
    const timer_user_data: u64 = 2;
    const cancel_user_data: u64 = 3;
    const client_recv_tag: usize = 0;
    const upstream_recv_tag: usize = 1;
    const client_send_tag: usize = 2;
    const upstream_send_tag: usize = 3;
    const tag_mask: usize = 3;

    pub fn init(allocator: std.mem.Allocator, io: Io, max_connections: usize) !Reactor {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
        if (max_connections == 0 or max_connections > max_connections_per_ring or
            max_connections > (std.math.maxInt(usize) - 1) / 2)
        {
            return error.InvalidReactorCapacity;
        }

        // Reserve one operation in each direction plus cancellation SQEs for
        // deterministic shutdown without overcommitting the submission ring.
        const required_entries = max_connections * 8 + 8;
        const completions = try allocator.alloc(linux.io_uring_cqe, required_entries);
        errdefer allocator.free(completions);
        const entries = try ringEntries(required_entries);
        var ring = try linux.IoUring.init(entries, 0);
        errdefer ring.deinit();

        const rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
        return switch (linux.errno(rc)) {
            .SUCCESS => .{
                .allocator = allocator,
                .io = io,
                .wake_fd = @intCast(rc),
                .max_connections = max_connections,
                .ring = ring,
                .completions = completions,
            },
            .MFILE, .NFILE, .NOMEM => error.SystemResources,
            else => error.Unexpected,
        };
    }

    pub fn deinit(self: *Reactor) void {
        self.stop();
        if (self.ring_live) self.ring.deinit();
        self.closePendingList(self.pending_head.swap(null, .acquire));
        _ = linux.close(self.wake_fd);
        self.allocator.free(self.completions);
        self.* = undefined;
    }

    pub fn stop(self: *Reactor) void {
        lockAdmission(&self.admission_mutex);
        const was_stopped = self.stopped.swap(true, .release);
        self.admission_mutex.unlock();
        if (was_stopped) return;
        self.wake();
    }

    pub fn adoptDuplicate(self: *Reactor, client: net.Stream, upstream: net.Stream) !void {
        try self.adoptDuplicateWithCleanup(client, upstream, null);
    }

    pub fn adoptDuplicateWithCleanup(
        self: *Reactor,
        client: net.Stream,
        upstream: net.Stream,
        cleanup: ?Cleanup,
    ) !void {
        if (builtin.os.tag != .linux) return error.UnsupportedOperatingSystem;
        const client_copy = try duplicateStream(client);
        errdefer client_copy.close(self.io);
        const upstream_copy = try duplicateStream(upstream);
        errdefer upstream_copy.close(self.io);

        const connection = try self.allocator.create(Connection);
        errdefer self.allocator.destroy(connection);
        connection.* = .{
            .client = client_copy,
            .upstream = upstream_copy,
            .last_activity = Io.Timestamp.now(self.io, .awake),
            .cleanup = cleanup,
        };

        lockAdmission(&self.admission_mutex);
        defer self.admission_mutex.unlock();
        if (self.stopped.load(.acquire)) return error.ReactorStopped;
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

    pub fn run(self: *Reactor) !void {
        var active_head: ?*Connection = null;
        defer {
            self.stop();
            self.ring.deinit();
            self.ring_live = false;
            self.closeActiveList(active_head);
            self.closePendingList(self.pending_head.swap(null, .acquire));
        }

        while (!self.stopped.load(.acquire)) {
            try Io.checkCancel(self.io);
            self.takePending(&active_head);
            self.serviceAll(&active_head);
            diagnostics.setRawReactorCount(self.active_count);
            try self.armOperations(active_head);
            _ = self.ring.submit_and_wait(1) catch |err| switch (err) {
                error.SignalInterrupt => continue,
                else => return err,
            };
            const count = try self.ring.copy_cqes(self.completions, 0);
            for (self.completions[0..count]) |completion| self.complete(completion);
        }
    }

    fn serviceAll(self: *Reactor, active_head: *?*Connection) void {
        const now = Io.Timestamp.now(self.io, .awake);
        var link = active_head;
        while (link.*) |connection| {
            if (connection.cleanup) |cleanup| {
                if (!cleanup.healthy()) connection.failed = true;
            }
            service(connection);
            if (idleExpired(connection, now)) connection.failed = true;
            if (connection.failed) self.cancelConnection(connection);
            if (finished(connection) and !hasPending(connection)) {
                link.* = connection.next;
                self.closeConnection(connection);
            } else {
                link = &connection.next;
            }
        }
        diagnostics.setRawReactorCount(self.active_count);
    }

    fn armOperations(self: *Reactor, active_head: ?*Connection) !void {
        if (!self.wake_pending) {
            _ = try self.ring.read(wake_user_data, self.wake_fd, .{ .buffer = std.mem.asBytes(&self.wake_value) }, 0);
            self.wake_pending = true;
        }
        if (!self.timer_pending) {
            _ = try self.ring.timeout(timer_user_data, &self.timer_spec, 0, 0);
            self.timer_pending = true;
        }
        var current = active_head;
        while (current) |connection| : (current = connection.next) {
            if (connection.failed) continue;
            if (!connection.client_recv_pending and !connection.client_eof and connection.client_to_upstream.empty()) {
                _ = try self.ring.recv(connectionUserData(connection, client_recv_tag), connection.client.socket.handle, .{ .buffer = &connection.client_to_upstream.bytes }, 0);
                connection.client_recv_pending = true;
            }
            if (!connection.upstream_recv_pending and !connection.upstream_eof and connection.upstream_to_client.empty()) {
                _ = try self.ring.recv(connectionUserData(connection, upstream_recv_tag), connection.upstream.socket.handle, .{ .buffer = &connection.upstream_to_client.bytes }, 0);
                connection.upstream_recv_pending = true;
            }
            if (!connection.upstream_send_pending and !connection.client_to_upstream.empty()) {
                _ = try self.ring.send(connectionUserData(connection, upstream_send_tag), connection.upstream.socket.handle, connection.client_to_upstream.readable(), linux.MSG.NOSIGNAL);
                connection.upstream_send_pending = true;
            }
            if (!connection.client_send_pending and !connection.upstream_to_client.empty()) {
                _ = try self.ring.send(connectionUserData(connection, client_send_tag), connection.client.socket.handle, connection.upstream_to_client.readable(), linux.MSG.NOSIGNAL);
                connection.client_send_pending = true;
            }
        }
        _ = try self.ring.submit();
    }

    fn complete(self: *Reactor, completion: linux.io_uring_cqe) void {
        if (completion.user_data == wake_user_data) {
            self.wake_pending = false;
            return;
        }
        if (completion.user_data == timer_user_data) {
            self.timer_pending = false;
            return;
        }
        if (completion.user_data == cancel_user_data) return;

        const pointer: usize = @intCast(completion.user_data & ~@as(u64, tag_mask));
        const connection: *Connection = @ptrFromInt(pointer);
        const tag: usize = @intCast(completion.user_data & tag_mask);
        const result = completion.res;
        const canceled = result < 0 and completionErrno(result) == .CANCELED;
        switch (tag) {
            client_recv_tag => {
                connection.client_recv_pending = false;
                if (result > 0) {
                    connection.client_to_upstream.end = @intCast(result);
                    connection.last_activity = Io.Timestamp.now(self.io, .awake);
                } else if (result == 0) connection.client_eof = true else if (!canceled) connection.failed = true;
            },
            upstream_recv_tag => {
                connection.upstream_recv_pending = false;
                if (result > 0) {
                    connection.upstream_to_client.end = @intCast(result);
                    connection.last_activity = Io.Timestamp.now(self.io, .awake);
                } else if (result == 0) connection.upstream_eof = true else if (!canceled) connection.failed = true;
            },
            client_send_tag => {
                connection.client_send_pending = false;
                if (result > 0) {
                    connection.upstream_to_client.start += @intCast(result);
                    if (connection.upstream_to_client.empty()) connection.upstream_to_client.reset();
                    connection.last_activity = Io.Timestamp.now(self.io, .awake);
                } else if (!canceled) connection.failed = true;
            },
            upstream_send_tag => {
                connection.upstream_send_pending = false;
                if (result > 0) {
                    connection.client_to_upstream.start += @intCast(result);
                    if (connection.client_to_upstream.empty()) connection.client_to_upstream.reset();
                    connection.last_activity = Io.Timestamp.now(self.io, .awake);
                } else if (!canceled) connection.failed = true;
            },
            else => unreachable,
        }
    }

    fn cancelConnection(self: *Reactor, connection: *Connection) void {
        if (connection.cancellation_requested) return;
        connection.cancellation_requested = true;
        if (connection.client_recv_pending) _ = self.ring.cancel(cancel_user_data, connectionUserData(connection, client_recv_tag), 0) catch {};
        if (connection.upstream_recv_pending) _ = self.ring.cancel(cancel_user_data, connectionUserData(connection, upstream_recv_tag), 0) catch {};
        if (connection.client_send_pending) _ = self.ring.cancel(cancel_user_data, connectionUserData(connection, client_send_tag), 0) catch {};
        if (connection.upstream_send_pending) _ = self.ring.cancel(cancel_user_data, connectionUserData(connection, upstream_send_tag), 0) catch {};
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
        if (connection.cleanup) |cleanup| cleanup.run();
        connection.client.close(self.io);
        connection.upstream.close(self.io);
        self.allocator.destroy(connection);
        if (self.active_count > 0) self.active_count -= 1;
    }

    fn closePending(self: *Reactor, connection: *Connection) void {
        if (connection.cleanup) |cleanup| cleanup.run();
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
};

fn service(connection: *Connection) void {
    if (connection.client_eof and connection.client_to_upstream.empty() and !connection.upstream_send_shutdown) {
        shutdownSend(connection.upstream.socket.handle);
        connection.upstream_send_shutdown = true;
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

fn hasPending(connection: *const Connection) bool {
    return connection.client_recv_pending or connection.upstream_recv_pending or
        connection.client_send_pending or connection.upstream_send_pending;
}

fn idleExpired(connection: *const Connection, now: Io.Timestamp) bool {
    return now.nanoseconds - connection.last_activity.nanoseconds >= connection_idle_timeout_ns;
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

fn connectionUserData(connection: *Connection, tag: usize) u64 {
    const pointer = @intFromPtr(connection);
    std.debug.assert(pointer & Reactor.tag_mask == 0);
    return @intCast(pointer | tag);
}

fn completionErrno(result: i32) linux.E {
    std.debug.assert(result < 0);
    return @enumFromInt(@as(u16, @intCast(-result)));
}

fn lockAdmission(mutex: *std.atomic.Mutex) void {
    while (!mutex.tryLock()) std.atomic.spinLoopHint();
}

fn ringEntries(required: usize) !u16 {
    if (required > maximum_ring_entries) return error.InvalidReactorCapacity;
    var entries: u16 = 8;
    while (entries < required) entries *= 2;
    return entries;
}

test "pending connections use a lock-free handoff stack" {
    var reactor: Reactor = .{
        .allocator = std.testing.allocator,
        .io = std.Io.failing,
        .wake_fd = -1,
        .max_connections = 2,
        .ring = undefined,
        .completions = undefined,
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

test "raw reactor cleanup callback has single-owner semantics" {
    const Counter = struct {
        fn increment(context: *anyopaque) void {
            const count: *usize = @ptrCast(@alignCast(context));
            count.* += 1;
        }
    };
    var count: usize = 0;
    var connection: Connection = .{
        .client = undefined,
        .upstream = undefined,
        .last_activity = .zero,
        .cleanup = .{ .context = &count, .callback = Counter.increment },
    };
    const cleanup = connection.cleanup.?;
    connection.cleanup = null;
    cleanup.run();
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expect(connection.cleanup == null);
}

test "raw reactor cleanup health callback can terminate hybrid ownership" {
    const Health = struct {
        fn reject(context: *anyopaque) bool {
            const called: *bool = @ptrCast(@alignCast(context));
            called.* = true;
            return false;
        }
        fn cleanup(_: *anyopaque) void {}
    };
    var called = false;
    const cleanup: Cleanup = .{
        .context = &called,
        .callback = Health.cleanup,
        .health_callback = Health.reject,
    };
    try std.testing.expect(!cleanup.healthy());
    try std.testing.expect(called);
}

test "io_uring completions preserve partial receive and send state" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    var reactor: Reactor = .{
        .allocator = std.testing.allocator,
        .io = threaded.io(),
        .wake_fd = -1,
        .max_connections = 1,
        .ring = undefined,
        .completions = undefined,
    };
    var connection: Connection = .{
        .client = undefined,
        .upstream = undefined,
        .last_activity = .zero,
        .client_recv_pending = true,
    };
    @memcpy(connection.client_to_upstream.bytes[0..6], "abcdef");

    reactor.complete(.{
        .user_data = connectionUserData(&connection, Reactor.client_recv_tag),
        .res = 6,
        .flags = 0,
    });
    try std.testing.expectEqualStrings("abcdef", connection.client_to_upstream.readable());
    try std.testing.expect(!connection.client_recv_pending);

    connection.upstream_send_pending = true;
    reactor.complete(.{
        .user_data = connectionUserData(&connection, Reactor.upstream_send_tag),
        .res = 2,
        .flags = 0,
    });
    try std.testing.expectEqualStrings("cdef", connection.client_to_upstream.readable());
    try std.testing.expect(!connection.upstream_send_pending);
}

test "canceled CQE clears ownership before failed connection can be freed" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{});
    defer threaded.deinit();
    var reactor: Reactor = .{
        .allocator = std.testing.allocator,
        .io = threaded.io(),
        .wake_fd = -1,
        .max_connections = 1,
        .ring = undefined,
        .completions = undefined,
    };
    var connection: Connection = .{
        .client = undefined,
        .upstream = undefined,
        .last_activity = .zero,
        .failed = true,
        .client_recv_pending = true,
        .cancellation_requested = true,
    };

    try std.testing.expect(finished(&connection));
    try std.testing.expect(hasPending(&connection));
    reactor.complete(.{
        .user_data = Reactor.cancel_user_data,
        .res = 0,
        .flags = 0,
    });
    try std.testing.expect(hasPending(&connection));
    reactor.complete(.{
        .user_data = connectionUserData(&connection, Reactor.client_recv_tag),
        .res = -@as(i32, @intFromEnum(linux.E.CANCELED)),
        .flags = 0,
    });
    try std.testing.expect(!hasPending(&connection));
    try std.testing.expect(connection.failed);
    try std.testing.expect(connection.cancellation_requested);
}

test "raw io_uring capacity is bounded before ring creation" {
    try std.testing.expectError(
        error.InvalidReactorCapacity,
        Reactor.init(std.testing.allocator, std.Io.failing, max_connections_per_ring + 1),
    );
    try std.testing.expectEqual(
        @as(u16, maximum_ring_entries),
        try ringEntries(max_connections_per_ring * 8 + 8),
    );
}

test "reactor shutdown cancels pending receives before connection free" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var threaded: Io.Threaded = .init(std.testing.allocator, .{
        .stack_size = 1024 * 1024,
        .concurrent_limit = .limited(2),
    });
    defer threaded.deinit();
    const io = threaded.io();

    var reactor = Reactor.init(std.testing.allocator, io, 1) catch return error.SkipZigTest;
    defer reactor.deinit();
    const client_pair = testSocketPair() catch return error.SkipZigTest;
    defer client_pair[0].close(io);
    defer client_pair[1].close(io);
    const upstream_pair = testSocketPair() catch return error.SkipZigTest;
    defer upstream_pair[0].close(io);
    defer upstream_pair[1].close(io);
    try reactor.adoptDuplicate(client_pair[0], upstream_pair[0]);

    var future = io.concurrent(runReactorTest, .{&reactor}) catch return error.SkipZigTest;
    defer _ = future.cancel(io) catch {};
    try io.sleep(.fromMilliseconds(10), .awake);
    reactor.stop();
    try future.await(io);
    try std.testing.expect(!reactor.ring_live);
    try std.testing.expectEqual(@as(usize, 0), reactor.active_count);
}

fn runReactorTest(reactor: *Reactor) Io.Cancelable!void {
    reactor.run() catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn testSocketPair() ![2]net.Stream {
    var fds: [2]posix.socket_t = undefined;
    while (true) switch (posix.errno(posix.system.socketpair(
        posix.AF.UNIX,
        posix.SOCK.STREAM | posix.SOCK.CLOEXEC,
        0,
        &fds,
    ))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.SocketPairFailed,
    };
    const address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    return .{
        .{ .socket = .{ .handle = fds[0], .address = address } },
        .{ .socket = .{ .handle = fds[1], .address = address } },
    };
}
