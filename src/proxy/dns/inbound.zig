const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const fakedns = @import("../../dns/fakedns.zig");
const dns_protocol = @import("../../dns/protocol.zig");
const dns_upstream = @import("../../dns/upstream.zig");

pub const Error = error{
    UnsupportedListenAddress,
    UnsupportedDnsUpstream,
    MissingDnsUpstream,
};

pub fn run(
    inbound: config.Inbound,
    dns_config: config.DnsConfig,
    fake_dns: *fakedns.Store,
    io: Io,
    log_writer: *Io.Writer,
    log_mutex: *Io.Mutex,
) !void {
    if (dns_config.servers.len == 0) return error.MissingDnsUpstream;
    var address = try bindAddress(inbound.listen, inbound.port);
    var socket = try address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    {
        try log_mutex.lock(io);
        defer log_mutex.unlock(io);
        try log_writer.print("dns inbound {s} listening on {f}\n", .{ inbound.tag orelse "-", socket.address });
        try log_writer.flush();
    }

    var packet_buffer: [4096]u8 = undefined;
    while (true) {
        const message = socket.receive(io, &packet_buffer) catch |err| switch (err) {
            error.Canceled => return err,
            else => |e| return e,
        };
        handleMessage(&socket, message.from, message.data, dns_config, fake_dns, io) catch {};
    }
}

fn handleMessage(
    socket: *const net.Socket,
    client_address: net.IpAddress,
    packet: []const u8,
    dns_config: config.DnsConfig,
    fake_dns: *fakedns.Store,
    io: Io,
) !void {
    var response_buffer: [4096]u8 = undefined;
    var name_buffer: [255]u8 = undefined;

    const question = dns_protocol.parseQuestion(packet, &name_buffer) catch {
        const response = try dns_protocol.buildErrorResponse(&response_buffer, packet, .format_error);
        try socket.send(io, &client_address, response);
        return;
    };

    if (question.qclass == dns_protocol.qclass_in and question.qtype == dns_protocol.qtype_a) {
        const fake_ip = try fake_dns.resolveA(question.name, io);
        const response = try dns_protocol.buildAResponse(&response_buffer, question, fake_ip, dns_config.fake_dns.ttl);
        try socket.send(io, &client_address, response);
        return;
    }

    if (question.qclass == dns_protocol.qclass_in and question.qtype == dns_protocol.qtype_aaaa) {
        const fake_ip = try fake_dns.resolveAAAA(question.name, io);
        const response = try dns_protocol.buildAAAAResponse(&response_buffer, question, fake_ip, dns_config.fake_dns.ttl);
        try socket.send(io, &client_address, response);
        return;
    }

    const server = dns_config.selectServer(question.name);
    const upstream = dns_upstream.parseAddress(server.resolver) catch return error.UnsupportedDnsUpstream;
    const forwarded = forward(packet, upstream, &response_buffer, io) catch {
        const response = try dns_protocol.buildErrorResponse(&response_buffer, packet, .server_failure);
        try socket.send(io, &client_address, response);
        return;
    };
    try socket.send(io, &client_address, forwarded);
}

fn forward(packet: []const u8, upstream: net.IpAddress, response_buffer: []u8, io: Io) ![]const u8 {
    var bind_address = anyAddressFor(upstream);
    var socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
    defer socket.close(io);

    try socket.send(io, &upstream, packet);
    const message = try socket.receiveTimeout(io, response_buffer, .{
        .duration = .{
            .raw = Io.Duration.fromSeconds(5),
            .clock = .awake,
        },
    });
    return message.data;
}

fn anyAddressFor(upstream: net.IpAddress) net.IpAddress {
    return switch (upstream) {
        .ip4 => .{ .ip4 = .{ .bytes = .{ 0, 0, 0, 0 }, .port = 0 } },
        .ip6 => .{ .ip6 = .{ .bytes = [_]u8{0} ** 16, .port = 0, .interface = .none } },
    };
}

fn bindAddress(listen: []const u8, port: u16) !net.IpAddress {
    return net.IpAddress.parse(listen, port) catch error.UnsupportedListenAddress;
}
