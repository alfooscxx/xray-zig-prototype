const std = @import("std");
const Io = std.Io;
const net = Io.net;

pub const Error = error{
    UnsupportedDnsUpstream,
};

pub fn parseAddress(text: []const u8) !net.IpAddress {
    var address = net.IpAddress.parseLiteral(text) catch return error.UnsupportedDnsUpstream;
    if (address.getPort() == 0) setPort(&address, 53);
    return address;
}

fn setPort(address: *net.IpAddress, port: u16) void {
    switch (address.*) {
        .ip4 => |*ip4| ip4.port = port,
        .ip6 => |*ip6| ip6.port = port,
    }
}

test "defaults DNS upstream port to 53" {
    const address = try parseAddress("8.8.8.8");
    try std.testing.expectEqual(@as(u16, 53), address.getPort());
}

test "preserves explicit DNS upstream port" {
    const address = try parseAddress("[2001:4860:4860::8888]:5353");
    try std.testing.expectEqual(@as(u16, 5353), address.getPort());
}
