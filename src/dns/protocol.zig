const std = @import("std");

pub const qtype_a: u16 = 1;
pub const qtype_aaaa: u16 = 28;
pub const qclass_in: u16 = 1;

pub const RCode = enum(u4) {
    no_error = 0,
    format_error = 1,
    server_failure = 2,
};

pub const Question = struct {
    id: u16,
    flags: u16,
    qtype: u16,
    qclass: u16,
    name: []const u8,
    question_wire: []const u8,
};

pub fn parseQuestion(packet: []const u8, name_buffer: []u8) !Question {
    if (packet.len < 12) return error.MalformedDnsPacket;
    const qdcount = std.mem.readInt(u16, packet[4..6], .big);
    if (qdcount != 1) return error.UnsupportedDnsPacket;

    var offset: usize = 12;
    var name_len: usize = 0;
    while (true) {
        if (offset >= packet.len) return error.MalformedDnsPacket;
        const label_len = packet[offset];
        offset += 1;
        if (label_len == 0) break;
        if ((label_len & 0xc0) != 0) return error.UnsupportedDnsPacket;
        if (label_len > 63) return error.MalformedDnsPacket;
        if (offset + label_len > packet.len) return error.MalformedDnsPacket;
        if (name_len != 0) {
            if (name_len >= name_buffer.len) return error.DomainTooLong;
            name_buffer[name_len] = '.';
            name_len += 1;
        }
        if (name_len + label_len > name_buffer.len) return error.DomainTooLong;
        for (packet[offset..][0..label_len]) |c| {
            name_buffer[name_len] = std.ascii.toLower(c);
            name_len += 1;
        }
        offset += label_len;
    }

    if (offset + 4 > packet.len) return error.MalformedDnsPacket;
    const question_end = offset + 4;
    return .{
        .id = std.mem.readInt(u16, packet[0..2], .big),
        .flags = std.mem.readInt(u16, packet[2..4], .big),
        .qtype = std.mem.readInt(u16, packet[offset..][0..2], .big),
        .qclass = std.mem.readInt(u16, packet[offset + 2 ..][0..2], .big),
        .name = name_buffer[0..name_len],
        .question_wire = packet[12..question_end],
    };
}

pub fn buildAResponse(out: []u8, question: Question, ip: [4]u8, ttl: u32) ![]const u8 {
    return buildAddressResponse(out, question, qtype_a, &ip, ttl);
}

pub fn buildAAAAResponse(out: []u8, question: Question, ip: [16]u8, ttl: u32) ![]const u8 {
    return buildAddressResponse(out, question, qtype_aaaa, &ip, ttl);
}

fn buildAddressResponse(out: []u8, question: Question, answer_type: u16, address: []const u8, ttl: u32) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    try writeHeader(&writer, question, .no_error, 1);
    try writer.writeAll(question.question_wire);
    try writeU16(&writer, 0xc00c);
    try writeU16(&writer, answer_type);
    try writeU16(&writer, qclass_in);
    try writeU32(&writer, ttl);
    try writeU16(&writer, @intCast(address.len));
    try writer.writeAll(address);
    return writer.buffered();
}

pub fn buildEmptyResponse(out: []u8, question: Question) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    try writeHeader(&writer, question, .no_error, 0);
    try writer.writeAll(question.question_wire);
    return writer.buffered();
}

pub fn buildErrorResponse(out: []u8, packet: []const u8, rcode: RCode) ![]const u8 {
    var writer: std.Io.Writer = .fixed(out);
    const id: u16 = if (packet.len >= 2) std.mem.readInt(u16, packet[0..2], .big) else 0;
    const flags: u16 = if (packet.len >= 4) std.mem.readInt(u16, packet[2..4], .big) else 0;
    try writeU16(&writer, id);
    try writeU16(&writer, responseFlags(flags, rcode));
    try writeU16(&writer, 0);
    try writeU16(&writer, 0);
    try writeU16(&writer, 0);
    try writeU16(&writer, 0);
    return writer.buffered();
}

fn writeHeader(writer: *std.Io.Writer, question: Question, rcode: RCode, answer_count: u16) !void {
    try writeU16(writer, question.id);
    try writeU16(writer, responseFlags(question.flags, rcode));
    try writeU16(writer, 1);
    try writeU16(writer, answer_count);
    try writeU16(writer, 0);
    try writeU16(writer, 0);
}

fn responseFlags(request_flags: u16, rcode: RCode) u16 {
    const rd = request_flags & 0x0100;
    return 0x8000 | rd | 0x0080 | @intFromEnum(rcode);
}

fn writeU16(writer: *std.Io.Writer, value: u16) !void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, value, .big);
    try writer.writeAll(&bytes);
}

fn writeU32(writer: *std.Io.Writer, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .big);
    try writer.writeAll(&bytes);
}

test "parses a single A question" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'E',  'x',  'a',
        'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    };
    var name_buffer: [255]u8 = undefined;
    const question = try parseQuestion(&packet, &name_buffer);
    try std.testing.expectEqualStrings("example.com", question.name);
    try std.testing.expectEqual(@as(u16, qtype_a), question.qtype);
}

test "builds an A response" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x01, 0x00, 0x01,
    };
    var name_buffer: [255]u8 = undefined;
    const question = try parseQuestion(&packet, &name_buffer);
    var out: [512]u8 = undefined;
    const response = try buildAResponse(&out, question, .{ 198, 18, 0, 1 }, 60);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, response[6..8], .big));
    try std.testing.expectEqualSlices(u8, &.{ 198, 18, 0, 1 }, response[response.len - 4 ..]);
}

test "builds an AAAA response" {
    const packet = [_]u8{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 'e',  'x',  'a',
        'm',  'p',  'l',  'e',  0x03, 'c',  'o',  'm',
        0x00, 0x00, 0x1c, 0x00, 0x01,
    };
    var name_buffer: [255]u8 = undefined;
    const question = try parseQuestion(&packet, &name_buffer);
    var out: [512]u8 = undefined;
    const ip = [_]u8{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12;
    const response = try buildAAAAResponse(&out, question, ip, 60);
    try std.testing.expectEqual(@as(u16, 1), std.mem.readInt(u16, response[6..8], .big));
    try std.testing.expectEqual(@as(u16, qtype_aaaa), std.mem.readInt(u16, response[response.len - 26 ..][0..2], .big));
    try std.testing.expectEqualSlices(u8, &ip, response[response.len - 16 ..]);
}
