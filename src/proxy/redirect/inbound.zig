const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const fakedns = @import("../../dns/fakedns.zig");
const log = @import("../../log.zig");
const monitoring = @import("../../monitoring.zig");
const session = @import("../../net/session.zig");
const sniff = @import("../../net/sniff.zig");

const linux = std.os.linux;
const so_original_dst = 80;
const ip6t_so_original_dst = 80;

pub const Error = error{
    RedirectRequiresLinux,
    OriginalDestinationUnavailable,
    UnsupportedOriginalDestination,
    UnsupportedListenAddress,
};

const AddressFamily = enum {
    ip4,
    ip6,
};

pub fn run(inbound: config.Inbound, dispatcher: session.Dispatcher, fake_dns: ?*fakedns.Store, io: Io, log_writer: *Io.Writer, log_mutex: *Io.Mutex) !void {
    var address = try bindAddress(inbound.listen, inbound.port);
    const address_family: AddressFamily = switch (address) {
        .ip4 => .ip4,
        .ip6 => .ip6,
    };
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    monitoring.registry.listenerStarted();
    defer monitoring.registry.listenerStopped();
    var group: Io.Group = .init;
    defer group.cancel(io);

    {
        try log_mutex.lock(io);
        defer log_mutex.unlock(io);
        try log_writer.print("redirect inbound {s} listening on {f}\n", .{ inbound.tag orelse "-", server.socket.address });
        try log_writer.flush();
    }

    while (true) {
        const stream = try server.accept(io);
        var capacity_warned = false;
        while (true) {
            group.concurrent(io, handleConnection, .{ stream, dispatcher, inbound.tag, fake_dns, address_family, io }) catch {
                if (!capacity_warned) {
                    log.warn("redirect inbound at worker capacity; queueing connection\n", .{});
                    capacity_warned = true;
                }
                io.sleep(Io.Duration.fromMilliseconds(10), .awake) catch |err| {
                    stream.close(io);
                    return err;
                };
                continue;
            };
            break;
        }
    }
}

fn bindAddress(listen: []const u8, port: u16) !net.IpAddress {
    return net.IpAddress.parse(listen, port) catch error.UnsupportedListenAddress;
}

fn handleConnection(stream: net.Stream, dispatcher: session.Dispatcher, inbound_tag: ?[]const u8, fake_dns: ?*fakedns.Store, address_family: AddressFamily, io: Io) Io.Cancelable!void {
    defer stream.close(io);

    const target = originalDestination(stream, address_family) catch |err| {
        log.warn("redirect inbound {s} original destination failed: {s}\n", .{ inbound_tag orelse "-", @errorName(err) });
        return;
    };

    if (fake_dns) |store| {
        if (store.lookup(target, io)) |found| {
            var lease = found;
            defer lease.release(io);
            const domain = lease.domain();
            const host = net.HostName.init(domain) catch return;
            dispatcher.dispatch(stream, .{
                .target = .{ .host = .{
                    .name = host,
                    .port = target.getPort(),
                } },
                .inbound_tag = inbound_tag,
                .sniffed_domain = domain,
                .preferred_family = std.meta.activeTag(target),
            }, .{}, io) catch |err| {
                log.warn("redirect dispatch failed: {s}\n", .{@errorName(err)});
                return;
            };
            return;
        }
    }

    var preface_buffer: [session.max_preface_len]u8 = undefined;
    const preface_len = peek(stream, &preface_buffer) catch 0;
    const sniffed_domain = sniff.domain(preface_buffer[0..preface_len]);

    dispatcher.dispatch(stream, .{
        .target = .{ .address = target },
        .inbound_tag = inbound_tag,
        .sniffed_domain = sniffed_domain,
    }, .{}, io) catch |err| {
        log.warn("redirect dispatch failed: {s}\n", .{@errorName(err)});
        return;
    };
}

fn originalDestination(stream: net.Stream, address_family: AddressFamily) !net.IpAddress {
    if (builtin.os.tag != .linux) return error.RedirectRequiresLinux;

    return switch (address_family) {
        .ip4 => originalDestination4(stream),
        .ip6 => originalDestination6(stream),
    };
}

fn originalDestination4(stream: net.Stream) !net.IpAddress {
    var addr: linux.sockaddr.in = undefined;
    var addr_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);
    const rc = linux.getsockopt(
        stream.socket.handle,
        linux.SOL.IP,
        so_original_dst,
        @ptrCast(std.mem.asBytes(&addr).ptr),
        &addr_len,
    );

    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT,
        .NOPROTOOPT,
        .INVAL,
        => return error.OriginalDestinationUnavailable,
        else => return error.OriginalDestinationUnavailable,
    }

    return ip4AddressFromSockaddr(addr);
}

fn originalDestination6(stream: net.Stream) !net.IpAddress {
    var addr: linux.sockaddr.in6 = undefined;
    var addr_len: linux.socklen_t = @sizeOf(linux.sockaddr.in6);
    const rc = linux.getsockopt(
        stream.socket.handle,
        linux.SOL.IPV6,
        ip6t_so_original_dst,
        @ptrCast(std.mem.asBytes(&addr).ptr),
        &addr_len,
    );

    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .NOENT,
        .NOPROTOOPT,
        .INVAL,
        => return error.OriginalDestinationUnavailable,
        else => return error.OriginalDestinationUnavailable,
    }

    return ip6AddressFromSockaddr(addr);
}

fn ip4AddressFromSockaddr(addr: linux.sockaddr.in) !net.IpAddress {
    if (addr.family != linux.AF.INET) return error.UnsupportedOriginalDestination;
    return .{ .ip4 = .{
        .bytes = std.mem.asBytes(&addr.addr)[0..4].*,
        .port = std.mem.bigToNative(u16, addr.port),
    } };
}

fn ip6AddressFromSockaddr(addr: linux.sockaddr.in6) !net.IpAddress {
    if (addr.family != linux.AF.INET6) return error.UnsupportedOriginalDestination;
    return .{ .ip6 = .{
        .bytes = addr.addr,
        .port = std.mem.bigToNative(u16, addr.port),
        .flow = addr.flowinfo,
        .interface = .{ .index = addr.scope_id },
    } };
}

fn peek(stream: net.Stream, buffer: []u8) !usize {
    if (builtin.os.tag != .linux) return error.RedirectRequiresLinux;
    if (buffer.len == 0) return 0;

    const rc = linux.recvfrom(
        stream.socket.handle,
        buffer.ptr,
        buffer.len,
        linux.MSG.PEEK,
        null,
        null,
    );

    return switch (linux.errno(rc)) {
        .SUCCESS => @intCast(rc),
        .INTR,
        .AGAIN,
        .CONNRESET,
        => 0,
        else => error.OriginalDestinationUnavailable,
    };
}

test "converts IPv4 original destination sockaddr" {
    var addr: linux.sockaddr.in = .{
        .family = linux.AF.INET,
        .port = std.mem.nativeToBig(u16, 443),
        .addr = 0,
    };
    std.mem.asBytes(&addr.addr).* = .{ 127, 0, 0, 1 };

    const target = try ip4AddressFromSockaddr(addr);
    switch (target) {
        .ip4 => |ip4| {
            try std.testing.expectEqual(@as(u16, 443), ip4.port);
            try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &ip4.bytes);
        },
        .ip6 => return error.UnexpectedIpv6,
    }
}

test "converts IPv6 original destination sockaddr" {
    const addr: linux.sockaddr.in6 = .{
        .family = linux.AF.INET6,
        .port = std.mem.nativeToBig(u16, 443),
        .flowinfo = 0,
        .addr = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
        .scope_id = 2,
    };

    const target = try ip6AddressFromSockaddr(addr);
    switch (target) {
        .ip6 => |ip6| {
            try std.testing.expectEqual(@as(u16, 443), ip6.port);
            try std.testing.expectEqualSlices(u8, &addr.addr, &ip6.bytes);
            try std.testing.expectEqual(@as(u32, 2), ip6.interface.index);
        },
        .ip4 => return error.UnexpectedIpv4,
    }
}
