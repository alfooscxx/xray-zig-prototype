const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const dns_client = @import("../../dns/client.zig");
const fakedns = @import("../../dns/fakedns.zig");
const dns_protocol = @import("../../dns/protocol.zig");
const log = @import("../../log.zig");
const session = @import("../../net/session.zig");

pub const Error = error{
    UnsupportedListenAddress,
    UnsupportedDnsUpstream,
    MissingDnsUpstream,
    DnsResponseTooLarge,
};

const max_inflight_queries = 16;
const OwnedPacket = struct {
    bytes: [4096]u8 = undefined,
    len: usize,

    fn init(bytes: []const u8) OwnedPacket {
        var packet: OwnedPacket = .{ .len = bytes.len };
        @memcpy(packet.bytes[0..bytes.len], bytes);
        return packet;
    }

    fn slice(packet: *const OwnedPacket) []const u8 {
        return packet.bytes[0..packet.len];
    }
};

pub fn run(
    inbound: config.Inbound,
    dns_config: config.DnsConfig,
    fake_dns: ?*fakedns.Store,
    dispatcher: session.Dispatcher,
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
    var group: Io.Group = .init;
    defer group.cancel(io);
    var query_slots: Io.Semaphore = .{ .permits = max_inflight_queries };

    while (true) {
        const message = socket.receive(io, &packet_buffer) catch |err| switch (err) {
            error.Canceled => return err,
            else => |e| return e,
        };

        try query_slots.wait(io);
        const packet = OwnedPacket.init(message.data);

        while (true) {
            group.concurrent(io, handleOwnedMessage, .{ &socket, message.from, packet, dns_config, fake_dns, dispatcher, &query_slots, io }) catch {
                io.sleep(Io.Duration.fromMilliseconds(10), .awake) catch |err| {
                    query_slots.post(io);
                    return err;
                };
                continue;
            };
            break;
        }
    }
}

fn handleOwnedMessage(
    socket: *const net.Socket,
    client_address: net.IpAddress,
    packet: OwnedPacket,
    dns_config: config.DnsConfig,
    fake_dns: ?*fakedns.Store,
    dispatcher: session.Dispatcher,
    query_slots: *Io.Semaphore,
    io: Io,
) Io.Cancelable!void {
    defer query_slots.post(io);
    handleMessage(socket, client_address, packet.slice(), dns_config, fake_dns, dispatcher, io) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return,
    };
}

fn handleMessage(
    socket: *const net.Socket,
    client_address: net.IpAddress,
    packet: []const u8,
    dns_config: config.DnsConfig,
    fake_dns: ?*fakedns.Store,
    dispatcher: session.Dispatcher,
    io: Io,
) !void {
    var response_buffer: [4096]u8 = undefined;
    var name_buffer: [255]u8 = undefined;

    const question = dns_protocol.parseQuestion(packet, &name_buffer) catch {
        const response = try dns_protocol.buildErrorResponse(&response_buffer, packet, .format_error);
        try socket.send(io, &client_address, response);
        return;
    };

    if (fake_dns) |store| {
        const fake_dns_config = dns_config.fake_dns.?;
        if (question.qclass == dns_protocol.qclass_in and question.qtype == dns_protocol.qtype_a) {
            const fake_ip = try store.resolveA(question.name, io);
            const response = try dns_protocol.buildAResponse(&response_buffer, question, fake_ip, fake_dns_config.ttl);
            try socket.send(io, &client_address, response);
            return;
        }

        if (question.qclass == dns_protocol.qclass_in and question.qtype == dns_protocol.qtype_aaaa) {
            const fake_ip = try store.resolveAAAA(question.name, io);
            const response = try dns_protocol.buildAAAAResponse(&response_buffer, question, fake_ip, fake_dns_config.ttl);
            try socket.send(io, &client_address, response);
            return;
        }
    }

    const server = dns_config.selectServer(question.name);
    const forwarded = dns_client.exchange(packet, question.name, server, dispatcher, &response_buffer, io) catch |err| {
        log.warn("dns query {s} via {s}/{s} failed: {s}\n", .{ question.name, server.resolver, server.outbound_tag, @errorName(err) });
        const response = try dns_protocol.buildErrorResponse(&response_buffer, packet, .server_failure);
        try socket.send(io, &client_address, response);
        return;
    };
    try socket.send(io, &client_address, forwarded);
}

fn bindAddress(listen: []const u8, port: u16) !net.IpAddress {
    return net.IpAddress.parse(listen, port) catch error.UnsupportedListenAddress;
}
