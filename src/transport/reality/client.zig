const std = @import("std");
const Io = std.Io;
const net = Io.net;

const config = @import("../../config/mod.zig");
const client_hello = @import("../tls/client_hello.zig");
const RealityTlsClient = @import("../tls/client.zig");
const tls_cipher_policy = @import("../tls/cipher_policy.zig");
const tls_fingerprint = @import("../tls/fingerprint.zig");

const AesGcm = std.crypto.aead.aes_gcm.Aes256Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const X25519 = std.crypto.dh.X25519;
const tls = std.crypto.tls;

const xray_client_version = [3]u8{ 26, 6, 1 };
const deadline_cancellation_poll_ns = std.time.ns_per_s;

pub const Error = error{
    InvalidRealityPublicKey,
    InvalidRealityShortId,
    InvalidRealityServerName,
    RealityClientHelloTooLarge,
    UnsupportedTlsFingerprint,
};

pub const ReadError = error{ReadPending};

pub const ParsedSettings = struct {
    server_name: []const u8,
    public_key: [32]u8,
    short_id: ShortId,
    fingerprint: tls_fingerprint.Fingerprint,
    cipher_policy: tls_cipher_policy.CipherPolicy,
};

pub const ShortId = struct {
    bytes: [8]u8 = @splat(0),
    len: u4 = 0,

    pub fn slice(self: *const ShortId) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub fn parseSettings(settings: config.RealitySettings) !ParsedSettings {
    return .{
        .server_name = settings.server_name,
        .public_key = try parsePublicKey(settings.public_key),
        .short_id = try parseShortId(settings.short_id),
        .fingerprint = settings.fingerprint,
        .cipher_policy = settings.cipher_policy,
    };
}

pub const Client = struct {
    stream: net.Stream,
    stream_reader: DeadlineStreamReader,
    stream_writer: DeadlineStreamWriter,
    tls_client: RealityTlsClient,
    tls_read_buffer: [RealityTlsClient.min_buffer_len]u8,
    tls_write_buffer: [RealityTlsClient.min_buffer_len]u8,
    socket_read_buffer: [RealityTlsClient.min_buffer_len]u8,
    socket_write_buffer: [RealityTlsClient.min_buffer_len]u8,
    direct_read: bool = false,
    direct_write: bool = false,

    pub fn init(self: *Client, stream: net.Stream, settings: config.RealitySettings, io: Io) !void {
        return self.initDeadline(stream, settings, io, null);
    }

    pub fn initDeadline(
        self: *Client,
        stream: net.Stream,
        settings: config.RealitySettings,
        io: Io,
        deadline: ?Io.Clock.Timestamp,
    ) !void {
        const parsed = try parseSettings(settings);
        if (parsed.server_name.len > std.math.maxInt(u16)) return error.InvalidRealityServerName;

        self.direct_read = false;
        self.direct_write = false;

        var entropy: [RealityTlsClient.Options.entropy_len]u8 = undefined;
        io.random(&entropy);
        entropy[32..64].* = [_]u8{0} ** 32;

        var key_material = client_hello.KeyMaterial.init(entropy[64..240]) catch |err| switch (err) {
            error.IdentityElement => return error.InvalidRealityPublicKey,
        };
        const auth_key = try deriveAuthKey(key_material.x25519_kp.secret_key, parsed.public_key, entropy[0..32].*);

        var hello_buf: [4096]u8 = undefined;
        const hello = try client_hello.buildHandshake(&hello_buf, .{
            .host = parsed.server_name,
            .entropy = &entropy,
            .fingerprint = parsed.fingerprint,
            .cipher_policy = parsed.cipher_policy,
        }, &key_material);
        const plain_session_id = makePlainSessionId(xray_client_version, currentUnixSeconds(io), parsed.short_id);
        entropy[32..64].* = sealSessionId(auth_key, entropy[0..32].*, hello, plain_session_id);

        self.stream = stream;
        self.stream_reader = .init(stream, io, &self.socket_read_buffer, deadline);
        self.stream_writer = .init(stream, io, &self.socket_write_buffer, deadline);
        self.tls_client = RealityTlsClient.init(
            &self.stream_reader.interface,
            &self.stream_writer.interface,
            .{
                .host = .{ .explicit = parsed.server_name },
                .ca = .no_verification,
                .read_buffer = &self.tls_read_buffer,
                .write_buffer = &self.tls_write_buffer,
                .entropy = &entropy,
                .realtime_now = Io.Timestamp.now(io, .real),
                .allow_truncation_attacks = true,
                .fingerprint = parsed.fingerprint,
                .cipher_policy = parsed.cipher_policy,
                .reality_auth_key = &auth_key,
            },
        ) catch |err| return switch (err) {
            error.WriteFailed => self.stream_writer.err orelse err,
            error.ReadFailed => self.stream_reader.err orelse err,
            else => |e| e,
        };
        self.stream_reader.deadline = null;
        self.stream_writer.deadline = null;
    }

    pub fn close(self: *Client, io: Io) void {
        if (!self.direct_write) self.tls_client.end() catch {};
        self.stream_writer.interface.flush() catch {};
        self.stream.close(io);
    }

    pub fn shutdownSend(self: *Client, io: Io) void {
        if (self.direct_write) {
            self.stream_writer.interface.flush() catch {};
            self.stream.shutdown(io, .send) catch {};
            return;
        }
        self.tls_client.end() catch {};
        self.stream_writer.interface.flush() catch {};
    }

    pub fn read(self: *Client, buffer: []u8) !usize {
        if (self.direct_read) return self.readRaw(buffer);
        if (self.copyDecrypted(buffer)) |n| return n;

        if (!hasCompleteTlsRecord(self.stream_reader.interface.buffered())) {
            self.stream_reader.interface.fillMore() catch |err| switch (err) {
                error.EndOfStream => return 0,
                else => |e| return e,
            };
            if (!hasCompleteTlsRecord(self.stream_reader.interface.buffered())) {
                return error.ReadPending;
            }
        }

        var data = [_][]u8{buffer};
        const n = self.tls_client.reader.readVec(&data) catch |err| switch (err) {
            error.EndOfStream => return 0,
            else => |e| return e,
        };
        if (n != 0) return n;
        if (self.copyDecrypted(buffer)) |decrypted_len| return decrypted_len;
        return error.ReadPending;
    }

    fn copyDecrypted(self: *Client, buffer: []u8) ?usize {
        const buffered = self.tls_client.reader.buffered();
        if (buffered.len == 0) return null;
        const n = @min(buffer.len, buffered.len);
        @memcpy(buffer[0..n], buffered[0..n]);
        self.tls_client.reader.toss(n);
        return n;
    }

    fn readRaw(self: *Client, buffer: []u8) !usize {
        const decrypted = self.tls_client.reader.buffered();
        if (decrypted.len != 0) {
            const n = @min(buffer.len, decrypted.len);
            @memcpy(buffer[0..n], decrypted[0..n]);
            self.tls_client.reader.toss(n);
            return n;
        }

        const buffered = self.stream_reader.interface.buffered();
        if (buffered.len != 0) {
            const n = @min(buffer.len, buffered.len);
            @memcpy(buffer[0..n], buffered[0..n]);
            self.stream_reader.interface.toss(n);
            return n;
        }
        var data = [_][]u8{buffer};
        return self.stream_reader.interface.readVec(&data);
    }

    pub fn readAll(self: *Client, buffer: []u8) !void {
        try self.tls_client.reader.readSliceAll(buffer);
    }

    pub fn writeAll(self: *Client, bytes: []const u8) !void {
        if (self.direct_write) {
            try self.stream_writer.interface.writeAll(bytes);
            return;
        }
        try self.tls_client.writer.writeAll(bytes);
    }

    pub fn flush(self: *Client) !void {
        if (!self.direct_write) try self.tls_client.writer.flush();
        try self.stream_writer.interface.flush();
    }

    pub fn enableDirectRead(self: *Client) void {
        self.direct_read = true;
    }

    pub fn enableDirectWrite(self: *Client) void {
        self.direct_write = true;
    }

    pub fn hasBufferedRead(self: *Client) bool {
        if (self.tls_client.reader.buffered().len != 0) return true;
        if (self.direct_read) return self.stream_reader.interface.buffered().len != 0;
        return hasCompleteTlsRecord(self.stream_reader.interface.buffered());
    }

    pub fn rawHandoffReady(self: *Client) bool {
        return self.direct_read and self.direct_write and
            self.tls_client.reader.buffered().len == 0 and
            self.stream_reader.interface.buffered().len == 0 and
            self.stream_writer.interface.buffered().len == 0;
    }
};

const DeadlineStreamReader = struct {
    io: Io,
    interface: Io.Reader,
    stream: net.Stream,
    err: ?anyerror = null,
    deadline: ?Io.Clock.Timestamp,

    fn init(stream: net.Stream, io: Io, buffer: []u8, deadline: ?Io.Clock.Timestamp) DeadlineStreamReader {
        return .{
            .io = io,
            .interface = .{
                .vtable = &.{
                    .stream = streamImpl,
                    .readVec = readVec,
                },
                .buffer = buffer,
                .seek = 0,
                .end = 0,
            },
            .stream = stream,
            .deadline = deadline,
        };
    }

    fn streamImpl(reader: *Io.Reader, writer: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try writer.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(reader, &data);
        writer.advance(n);
        return n;
    }

    fn readVec(reader: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const self: *DeadlineStreamReader = @alignCast(@fieldParentPtr("interface", reader));
        var iovecs_buffer: [8][]u8 = undefined;
        const dest_n, const data_size = try reader.writableVector(&iovecs_buffer, data);
        const dest = iovecs_buffer[0..dest_n];
        std.debug.assert(dest[0].len > 0);

        waitReady(self.io, self.stream.socket.handle, std.posix.POLL.IN, self.deadline) catch |err| {
            self.err = err;
            return error.ReadFailed;
        };
        const n = self.io.vtable.netRead(self.io.userdata, self.stream.socket.handle, dest) catch |err| {
            self.err = err;
            return error.ReadFailed;
        };
        if (n == 0) return error.EndOfStream;
        if (n > data_size) {
            self.interface.end += n - data_size;
            return data_size;
        }
        return n;
    }
};

const DeadlineStreamWriter = struct {
    io: Io,
    interface: Io.Writer,
    stream: net.Stream,
    err: ?anyerror = null,
    deadline: ?Io.Clock.Timestamp,

    fn init(stream: net.Stream, io: Io, buffer: []u8, deadline: ?Io.Clock.Timestamp) DeadlineStreamWriter {
        return .{
            .io = io,
            .interface = .{
                .vtable = &.{ .drain = drain },
                .buffer = buffer,
            },
            .stream = stream,
            .deadline = deadline,
        };
    }

    fn drain(writer: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const self: *DeadlineStreamWriter = @alignCast(@fieldParentPtr("interface", writer));
        waitReady(self.io, self.stream.socket.handle, std.posix.POLL.OUT, self.deadline) catch |err| {
            self.err = err;
            return error.WriteFailed;
        };
        const n = self.io.vtable.netWrite(
            self.io.userdata,
            self.stream.socket.handle,
            writer.buffered(),
            data,
            splat,
        ) catch |err| {
            self.err = err;
            return error.WriteFailed;
        };
        return writer.consume(n);
    }
};

fn waitReady(
    io: Io,
    handle: net.Socket.Handle,
    events: i16,
    deadline: ?Io.Clock.Timestamp,
) !void {
    const end = deadline orelse return;
    var descriptor = [1]std.posix.pollfd{.{
        .fd = handle,
        .events = events,
        .revents = 0,
    }};

    while (true) {
        try io.checkCancel();
        const remaining_ns = end.durationFromNow(io).raw.toNanoseconds();
        if (remaining_ns <= 0) return error.Timeout;
        const poll_ns = @min(remaining_ns, deadline_cancellation_poll_ns);
        var timeout: std.posix.timespec = .{
            .sec = @intCast(@divTrunc(poll_ns, std.time.ns_per_s)),
            .nsec = @intCast(@mod(poll_ns, std.time.ns_per_s)),
        };
        const ready = std.posix.ppoll(&descriptor, &timeout, null) catch |err| switch (err) {
            error.SignalInterrupt => continue,
            else => |e| return e,
        };
        if (ready == 0) continue;
        return;
    }
}

fn hasCompleteTlsRecord(bytes: []const u8) bool {
    if (bytes.len < tls.record_header_len) return false;
    const record_len = std.mem.readInt(u16, bytes[3..5], .big);
    if (record_len > tls.max_ciphertext_len) return true;
    return bytes.len >= tls.record_header_len + @as(usize, record_len);
}

pub fn wrap(out: *Client, stream: net.Stream, settings: config.RealitySettings, io: Io) !void {
    try out.init(stream, settings, io);
}

pub fn parsePublicKey(text: []const u8) ![32]u8 {
    var out: [32]u8 = undefined;

    if (std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(text)) |len| {
        if (len == out.len) {
            try std.base64.url_safe_no_pad.Decoder.decode(&out, text);
            return out;
        }
    } else |_| {}

    if (std.base64.url_safe.Decoder.calcSizeForSlice(text)) |len| {
        if (len == out.len) {
            try std.base64.url_safe.Decoder.decode(&out, text);
            return out;
        }
    } else |_| {}

    return error.InvalidRealityPublicKey;
}

pub fn parseShortId(text: []const u8) !ShortId {
    if (text.len > 16 or text.len % 2 != 0) return error.InvalidRealityShortId;

    var out: ShortId = .{};
    var i: usize = 0;
    while (i < text.len) : (i += 2) {
        const hi = hexValue(text[i]) orelse return error.InvalidRealityShortId;
        const lo = hexValue(text[i + 1]) orelse return error.InvalidRealityShortId;
        out.bytes[out.len] = (hi << 4) | lo;
        out.len += 1;
    }
    return out;
}

pub fn deriveAuthKey(client_secret: [32]u8, server_public: [32]u8, hello_random: [32]u8) ![32]u8 {
    const shared = try X25519.scalarmult(client_secret, server_public);
    const prk = HkdfSha256.extract(hello_random[0..20], &shared);
    var out: [32]u8 = undefined;
    HkdfSha256.expand(&out, "REALITY", prk);
    return out;
}

pub fn makePlainSessionId(version: [3]u8, unix_time: u32, short_id: ShortId) [16]u8 {
    var session_id: [16]u8 = @splat(0);
    session_id[0..3].* = version;
    session_id[3] = 0;
    std.mem.writeInt(u32, session_id[4..8], unix_time, .big);
    @memcpy(session_id[8..][0..short_id.len], short_id.slice());
    return session_id;
}

pub fn sealSessionId(auth_key: [32]u8, hello_random: [32]u8, hello_raw: []const u8, plain_session_id: [16]u8) [32]u8 {
    var ciphertext: [16]u8 = undefined;
    var tag: [16]u8 = undefined;
    AesGcm.encrypt(&ciphertext, &tag, &plain_session_id, hello_raw, hello_random[20..32].*, auth_key);

    var sealed: [32]u8 = undefined;
    sealed[0..16].* = ciphertext;
    sealed[16..32].* = tag;
    return sealed;
}

fn currentUnixSeconds(io: Io) u32 {
    const timestamp = Io.Timestamp.now(io, .real);
    const seconds = timestamp.toSeconds();
    if (seconds <= 0) return 0;
    return @intCast(@min(seconds, std.math.maxInt(u32)));
}

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

test "parses base64url public key" {
    const encoded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const key = try parsePublicKey(encoded);
    try std.testing.expectEqual([_]u8{0} ** 32, key);
}

test "parses short id hex" {
    const short_id = try parseShortId("0123456789abcdef");
    try std.testing.expectEqual(@as(u4, 8), short_id.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }, short_id.slice());
}

test "recognizes complete buffered TLS records" {
    try std.testing.expect(!hasCompleteTlsRecord(&.{ 0x17, 0x03, 0x03, 0x00 }));
    try std.testing.expect(!hasCompleteTlsRecord(&.{ 0x17, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb }));
    try std.testing.expect(hasCompleteTlsRecord(&.{ 0x17, 0x03, 0x03, 0x00, 0x03, 0xaa, 0xbb, 0xcc }));
}

test "REALITY initialization times out when the peer stalls" {
    var threaded: Io.Threaded = .init(std.testing.allocator, .{
        .stack_size = 1024 * 1024,
        .concurrent_limit = .limited(2),
    });
    defer threaded.deinit();
    const io = threaded.io();

    var handles: [2]std.posix.socket_t = undefined;
    while (true) switch (std.posix.errno(std.posix.system.socketpair(
        std.posix.AF.UNIX,
        std.posix.SOCK.STREAM | std.posix.SOCK.CLOEXEC,
        0,
        &handles,
    ))) {
        .SUCCESS => break,
        .INTR => continue,
        else => return error.SystemResources,
    };
    defer _ = std.posix.system.close(handles[0]);
    defer _ = std.posix.system.close(handles[1]);
    const address = net.IpAddress.parse("127.0.0.1", 0) catch unreachable;
    const stream: net.Stream = .{ .socket = .{ .handle = handles[0], .address = address } };
    const deadline = Io.Clock.Timestamp.fromNow(io, .{
        .raw = Io.Duration.fromMilliseconds(100),
        .clock = .awake,
    });
    var client: Client = undefined;
    try std.testing.expectError(error.Timeout, client.initDeadline(stream, .{
        .server_name = "www.google.com",
        .public_key = "E59WjnvZcQMu7tR7_BgyhycuEdBS-CtKxfImRCdAvFM",
        .short_id = "0123456789abcdef",
        .fingerprint = .firefox,
    }, io, deadline));
}

test "keeps parsed fingerprint and cipher profiles" {
    const settings: config.RealitySettings = .{
        .server_name = "www.example.com",
        .public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        .short_id = "0123456789abcdef",
        .fingerprint = .firefox,
        .cipher_policy = .chacha20_only,
    };

    const parsed = try parseSettings(settings);
    try std.testing.expectEqual(tls_fingerprint.Fingerprint.firefox, parsed.fingerprint);
    try std.testing.expectEqual(tls_cipher_policy.CipherPolicy.chacha20_only, parsed.cipher_policy);
}

test "mirrors local TLS ClientHello bytes for Reality AAD" {
    var entropy: [RealityTlsClient.Options.entropy_len]u8 = undefined;
    for (&entropy, 0..) |*byte, i| byte.* = @intCast((i * 31 + 7) & 0xff);
    entropy[32..64].* = [_]u8{0} ** 32;
    var key_material = try client_hello.KeyMaterial.init(entropy[64..240]);

    var expected_buffer: [4096]u8 = undefined;
    const expected = try client_hello.buildHandshake(&expected_buffer, .{
        .host = "www.google.com",
        .entropy = &entropy,
        .fingerprint = .firefox,
        .cipher_policy = .chacha20_only,
    }, &key_material);

    var input_buffer: [RealityTlsClient.min_buffer_len]u8 = @splat(0);
    var input: Io.Reader = .fixed(&input_buffer);
    var output_buffer: [4096]u8 = undefined;
    var output: Io.Writer = .fixed(&output_buffer);
    var tls_read_buffer: [RealityTlsClient.min_buffer_len]u8 = undefined;
    var tls_write_buffer: [RealityTlsClient.min_buffer_len]u8 = undefined;

    _ = RealityTlsClient.init(&input, &output, .{
        .host = .{ .explicit = "www.google.com" },
        .ca = .no_verification,
        .read_buffer = &tls_read_buffer,
        .write_buffer = &tls_write_buffer,
        .entropy = &entropy,
        .realtime_now = Io.Timestamp.zero,
        .fingerprint = .firefox,
        .cipher_policy = .chacha20_only,
    }) catch {};

    const actual_record = output.buffered();
    try std.testing.expect(actual_record.len > tls.record_header_len);
    try std.testing.expectEqualSlices(u8, expected, actual_record[tls.record_header_len..]);
}

test "derives and seals session id deterministically" {
    const server_secret: [32]u8 = @splat(7);
    const server_public = try X25519.recoverPublicKey(server_secret);
    const client_secret: [32]u8 = @splat(9);
    var hello_random: [32]u8 = undefined;
    for (&hello_random, 0..) |*byte, i| byte.* = @intCast(i);

    const auth_key = try deriveAuthKey(client_secret, server_public, hello_random);
    const short_id = try parseShortId("01020304");
    const plain = makePlainSessionId(.{ 25, 1, 1 }, 1_700_000_000, short_id);
    const sealed = sealSessionId(auth_key, hello_random, "client hello raw", plain);

    try std.testing.expect(!std.mem.eql(u8, &plain, sealed[0..16]));
    try std.testing.expectEqual(@as(usize, 32), sealed.len);
}
