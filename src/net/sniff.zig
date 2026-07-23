const std = @import("std");

pub fn domain(bytes: []const u8) ?[]const u8 {
    return tlsSni(bytes) orelse httpHost(bytes);
}

pub fn httpHost(bytes: []const u8) ?[]const u8 {
    if (!looksLikeHttp(bytes)) return null;

    var pos: usize = 0;
    while (pos < bytes.len) {
        const line_end = std.mem.indexOfPos(u8, bytes, pos, "\r\n") orelse return null;
        const line = bytes[pos..line_end];
        pos = line_end + 2;

        if (line.len == 0) return null;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "host")) continue;

        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (value.len == 0) return null;
        return stripOptionalPort(value);
    }
    return null;
}

pub fn tlsSni(bytes: []const u8) ?[]const u8 {
    if (bytes.len < 5) return null;
    if (bytes[0] != 0x16) return null;

    const record_len = readInt(u16, bytes[3..5]);
    if (record_len < 4 or bytes.len < 5 + @as(usize, record_len)) return null;
    var cursor: usize = 5;
    const record_end = cursor + record_len;

    const handshake_type = takeByte(bytes, &cursor, record_end) orelse return null;
    if (handshake_type != 0x01) return null;
    const handshake_len = takeU24(bytes, &cursor, record_end) orelse return null;
    if (cursor + handshake_len > record_end) return null;
    const hello_end = cursor + handshake_len;

    if (!skip(bytes, &cursor, hello_end, 2 + 32)) return null;
    const session_id_len = takeByte(bytes, &cursor, hello_end) orelse return null;
    if (!skip(bytes, &cursor, hello_end, session_id_len)) return null;

    const cipher_suites_len = takeU16(bytes, &cursor, hello_end) orelse return null;
    if (!skip(bytes, &cursor, hello_end, cipher_suites_len)) return null;

    const compression_methods_len = takeByte(bytes, &cursor, hello_end) orelse return null;
    if (!skip(bytes, &cursor, hello_end, compression_methods_len)) return null;

    const extensions_len = takeU16(bytes, &cursor, hello_end) orelse return null;
    if (cursor + extensions_len > hello_end) return null;
    const extensions_end = cursor + extensions_len;

    while (cursor + 4 <= extensions_end) {
        const extension_type = takeU16(bytes, &cursor, extensions_end) orelse return null;
        const extension_len = takeU16(bytes, &cursor, extensions_end) orelse return null;
        if (cursor + extension_len > extensions_end) return null;
        const extension_end = cursor + extension_len;

        if (extension_type == 0x0000) {
            return parseServerNameExtension(bytes[cursor..extension_end]);
        }
        cursor = extension_end;
    }

    return null;
}

fn parseServerNameExtension(extension: []const u8) ?[]const u8 {
    if (extension.len < 2) return null;
    var cursor: usize = 0;
    const list_len = takeU16(extension, &cursor, extension.len) orelse return null;
    if (cursor + list_len > extension.len) return null;
    const list_end = cursor + list_len;

    while (cursor + 3 <= list_end) {
        const name_type = takeByte(extension, &cursor, list_end) orelse return null;
        const name_len = takeU16(extension, &cursor, list_end) orelse return null;
        if (cursor + name_len > list_end) return null;
        const name = extension[cursor .. cursor + name_len];
        cursor += name_len;

        if (name_type == 0 and name.len > 0) return name;
    }
    return null;
}

fn looksLikeHttp(bytes: []const u8) bool {
    const methods = [_][]const u8{
        "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ",
    };
    for (methods) |method| {
        if (std.mem.startsWith(u8, bytes, method)) return true;
    }
    return false;
}

fn stripOptionalPort(value: []const u8) []const u8 {
    if (value[0] == '[') return value;
    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return value;
    if (std.mem.indexOfScalar(u8, value[0..colon], ':') != null) return value;
    if (colon + 1 == value.len) return value;
    for (value[colon + 1 ..]) |c| {
        if (!std.ascii.isDigit(c)) return value;
    }
    return value[0..colon];
}

fn takeByte(bytes: []const u8, cursor: *usize, end: usize) ?u8 {
    if (cursor.* >= end or cursor.* >= bytes.len) return null;
    const value = bytes[cursor.*];
    cursor.* += 1;
    return value;
}

fn takeU16(bytes: []const u8, cursor: *usize, end: usize) ?usize {
    if (cursor.* + 2 > end or cursor.* + 2 > bytes.len) return null;
    const value = readInt(u16, bytes[cursor.* .. cursor.* + 2]);
    cursor.* += 2;
    return value;
}

fn takeU24(bytes: []const u8, cursor: *usize, end: usize) ?usize {
    if (cursor.* + 3 > end or cursor.* + 3 > bytes.len) return null;
    const value = (@as(usize, bytes[cursor.*]) << 16) |
        (@as(usize, bytes[cursor.* + 1]) << 8) |
        @as(usize, bytes[cursor.* + 2]);
    cursor.* += 3;
    return value;
}

fn skip(bytes: []const u8, cursor: *usize, end: usize, amount: usize) bool {
    if (cursor.* + amount > end or cursor.* + amount > bytes.len) return false;
    cursor.* += amount;
    return true;
}

fn readInt(comptime T: type, bytes: []const u8) T {
    var buffer: [@sizeOf(T)]u8 = undefined;
    @memcpy(&buffer, bytes[0..buffer.len]);
    return std.mem.readInt(T, &buffer, .big);
}

test "sniffs HTTP Host header" {
    const request =
        "GET / HTTP/1.1\r\n" ++
        "Host: www.example.com:443\r\n" ++
        "User-Agent: test\r\n\r\n";
    try std.testing.expectEqualStrings("www.example.com", httpHost(request).?);
}

test "sniffs TLS SNI" {
    const hello =
        [_]u8{ 0x16, 0x03, 0x01, 0x00, 0x43, 0x01, 0x00, 0x00, 0x3f, 0x03, 0x03 } ++
        ([_]u8{0} ** 32) ++
        [_]u8{
            0x00,
            0x00,
            0x02,
            0x13,
            0x01,
            0x01,
            0x00,
            0x00,
            0x14,
            0x00,
            0x00,
            0x00,
            0x10,
            0x00,
            0x0e,
            0x00,
            0x00,
            0x0b,
            'e',
            'x',
            'a',
            'm',
            'p',
            'l',
            'e',
            '.',
            'c',
            'o',
            'm',
        };

    try std.testing.expectEqualStrings("example.com", tlsSni(&hello).?);
}
