const std = @import("std");
const Io = std.Io;
const tls = std.crypto.tls;
const crypto = std.crypto;

const cipher_policy = @import("cipher_policy.zig");
const tls_fingerprint = @import("fingerprint.zig");

pub const entropy_len = 240;

pub const BuildOptions = struct {
    host: []const u8,
    entropy: *const [entropy_len]u8,
    fingerprint: tls_fingerprint.Fingerprint,
    cipher_policy: cipher_policy.CipherPolicy = cipher_policy.default_policy,
    session_id: ?[]const u8 = null,
};

pub const KeyMaterial = struct {
    ml_kem768_kp: crypto.kem.ml_kem.MLKem768.KeyPair,
    secp256r1_kp: crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
    secp384r1_kp: crypto.sign.ecdsa.EcdsaP384Sha384.KeyPair,
    x25519_kp: crypto.dh.X25519.KeyPair,
    sk_buf: [sk_max_len]u8,
    sk_len: std.math.IntFittingRange(0, sk_max_len),

    const sk_max_len = @max(
        crypto.dh.X25519.shared_length + crypto.kem.ml_kem.MLKem768.shared_length,
        crypto.ecc.P256.scalar.encoded_length,
        crypto.ecc.P384.scalar.encoded_length,
        crypto.dh.X25519.shared_length,
    );

    pub fn init(seed: *const [176]u8) error{IdentityElement}!KeyMaterial {
        return .{
            .ml_kem768_kp = try .generateDeterministic(seed[0..64].*),
            .secp256r1_kp = try .generateDeterministic(seed[64..96].*),
            .secp384r1_kp = try .generateDeterministic(seed[96..144].*),
            .x25519_kp = try .generateDeterministic(seed[144..176].*),
            .sk_buf = undefined,
            .sk_len = 0,
        };
    }

    pub fn exchange(
        km: *KeyMaterial,
        named_group: tls.NamedGroup,
        server_pub_key: []const u8,
    ) error{ TlsIllegalParameter, TlsDecryptFailure }!void {
        switch (named_group) {
            .x25519_ml_kem768 => {
                const hksl = crypto.kem.ml_kem.MLKem768.ciphertext_length;
                const xksl = hksl + crypto.dh.X25519.public_length;
                if (server_pub_key.len != xksl) return error.TlsIllegalParameter;

                const hsk = km.ml_kem768_kp.secret_key.decaps(server_pub_key[0..hksl]) catch
                    return error.TlsDecryptFailure;
                const xsk = crypto.dh.X25519.scalarmult(km.x25519_kp.secret_key, server_pub_key[hksl..xksl].*) catch
                    return error.TlsDecryptFailure;
                @memcpy(km.sk_buf[0..hsk.len], &hsk);
                @memcpy(km.sk_buf[hsk.len..][0..xsk.len], &xsk);
                km.sk_len = hsk.len + xsk.len;
            },
            .secp256r1 => {
                const PublicKey = crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey;
                const pk = PublicKey.fromSec1(server_pub_key) catch return error.TlsDecryptFailure;
                const mul = pk.p.mulPublic(km.secp256r1_kp.secret_key.bytes, .big) catch
                    return error.TlsDecryptFailure;
                const sk = mul.affineCoordinates().x.toBytes(.big);
                @memcpy(km.sk_buf[0..sk.len], &sk);
                km.sk_len = sk.len;
            },
            .secp384r1 => {
                const PublicKey = crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey;
                const pk = PublicKey.fromSec1(server_pub_key) catch return error.TlsDecryptFailure;
                const mul = pk.p.mulPublic(km.secp384r1_kp.secret_key.bytes, .big) catch
                    return error.TlsDecryptFailure;
                const sk = mul.affineCoordinates().x.toBytes(.big);
                @memcpy(km.sk_buf[0..sk.len], &sk);
                km.sk_len = sk.len;
            },
            .x25519 => {
                const ksl = crypto.dh.X25519.public_length;
                if (server_pub_key.len != ksl) return error.TlsIllegalParameter;
                const sk = crypto.dh.X25519.scalarmult(km.x25519_kp.secret_key, server_pub_key[0..ksl].*) catch
                    return error.TlsDecryptFailure;
                @memcpy(km.sk_buf[0..sk.len], &sk);
                km.sk_len = sk.len;
            },
            else => return error.TlsIllegalParameter,
        }
    }

    pub fn getSharedSecret(km: *const KeyMaterial) ?[]const u8 {
        return if (km.sk_len > 0) km.sk_buf[0..km.sk_len] else null;
    }
};

pub fn buildHandshake(out: []u8, options: BuildOptions, key_material: *const KeyMaterial) ![]const u8 {
    if (!options.fingerprint.isFirefoxLike()) return error.UnsupportedTlsFingerprint;
    if (options.host.len > std.math.maxInt(u16)) return error.InvalidServerName;

    const session_id = options.session_id orelse options.entropy[32..64];
    if (session_id.len > 32) return error.InvalidSessionId;

    var writer: Io.Writer = .fixed(out);
    try writer.writeByte(@intFromEnum(tls.HandshakeType.client_hello));
    const handshake_len_pos = writer.end;
    try writer.writeAll(&.{ 0, 0, 0 });
    const client_hello_start = writer.end;

    try writeU16(&writer, @intFromEnum(tls.ProtocolVersion.tls_1_2));
    try writer.writeAll(options.entropy[0..32]);
    try writer.writeByte(@intCast(session_id.len));
    try writer.writeAll(session_id);

    try writeCipherSuites(&writer, cipherSuites(options.cipher_policy));
    try writer.writeByte(1);
    try writer.writeByte(@intFromEnum(tls.CompressionMethod.null));

    const extensions_len_pos = writer.end;
    try writeU16(&writer, 0);
    switch (options.fingerprint) {
        .firefox,
        .hellofirefox_105,
        => try writeFirefox105Extensions(&writer, options, key_material),
        .hellofirefox_148 => try writeFirefox148Extensions(&writer, options, key_material),
        .hellofirefox_120 => try writeFirefox120Extensions(&writer, options, key_material),
        else => unreachable,
    }
    patchU16(writer.buffer[extensions_len_pos..][0..2], @intCast(writer.end - extensions_len_pos - 2));

    patchU24(writer.buffer[handshake_len_pos..][0..3], @intCast(writer.end - client_hello_start));
    return writer.buffered();
}

pub fn buildRecord(out: []u8, handshake: []const u8) ![]const u8 {
    var writer: Io.Writer = .fixed(out);
    try writer.writeByte(@intFromEnum(tls.ContentType.handshake));
    try writeU16(&writer, @intFromEnum(tls.ProtocolVersion.tls_1_0));
    try writeU16(&writer, handshake.len);
    try writer.writeAll(handshake);
    return writer.buffered();
}

const firefox_cipher_suites = [_]u16{
    0x1301, 0x1303, 0x1302,
    0xc02b, 0xc02f, 0xcca9,
    0xcca8, 0xc02c, 0xc030,
    0xc00a, 0xc009, 0xc013,
    0xc014, 0x009c, 0x009d,
    0x002f, 0x0035,
};

const chacha20_cipher_suites = [_]u16{
    0x1303, // TLS_CHACHA20_POLY1305_SHA256
    0xcca9, // ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    0xcca8, // ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
};

fn cipherSuites(policy: cipher_policy.CipherPolicy) []const u16 {
    return switch (policy) {
        .firefox => &firefox_cipher_suites,
        .chacha20_only => &chacha20_cipher_suites,
    };
}

fn writeFirefox148Extensions(writer: *Io.Writer, options: BuildOptions, key_material: *const KeyMaterial) !void {
    try writeServerName(writer, options.host);
    try writeEmptyExtension(writer, 23); // extended_master_secret
    try writeRenegotiationInfo(writer);
    try writeU16ListExtension(writer, @intFromEnum(tls.ExtensionType.supported_groups), &.{
        @intFromEnum(tls.NamedGroup.x25519_ml_kem768),
        @intFromEnum(tls.NamedGroup.x25519),
        @intFromEnum(tls.NamedGroup.secp256r1),
        @intFromEnum(tls.NamedGroup.secp384r1),
        0x0019, // secp521r1
        0x0100, // ffdhe2048
        0x0101, // ffdhe3072
    });
    try writeSupportedPoints(writer);
    try writeAlpn(writer);
    try writeStatusRequest(writer);
    try writeDelegatedCredentials(writer);
    try writeEmptyExtension(writer, @intFromEnum(tls.ExtensionType.signed_certificate_timestamp));
    try writeKeyShare148(writer, key_material);
    try writeSupportedVersions(writer);
    try writeSignatureAlgorithms(writer);
    try writeRecordSizeLimit(writer);
    try writeCompressCertificate(writer, &.{ 0x0001, 0x0002, 0x0003 });
}

fn writeFirefox105Extensions(writer: *Io.Writer, options: BuildOptions, key_material: *const KeyMaterial) !void {
    try writeServerName(writer, options.host);
    try writeEmptyExtension(writer, 23);
    try writeRenegotiationInfo(writer);
    try writeU16ListExtension(writer, @intFromEnum(tls.ExtensionType.supported_groups), &.{
        @intFromEnum(tls.NamedGroup.x25519),
        @intFromEnum(tls.NamedGroup.secp256r1),
        @intFromEnum(tls.NamedGroup.secp384r1),
        0x0019,
        0x0100,
        0x0101,
    });
    try writeSupportedPoints(writer);
    try writeEmptyExtension(writer, 35); // session_ticket
    try writeAlpn(writer);
    try writeStatusRequest(writer);
    try writeDelegatedCredentials(writer);
    try writeKeyShare120(writer, key_material);
    try writeSupportedVersions(writer);
    try writeSignatureAlgorithms(writer);
    try writePskModes(writer);
    try writeRecordSizeLimit(writer);
    try writeBoringPadding(writer);
}

fn writeFirefox120Extensions(writer: *Io.Writer, options: BuildOptions, key_material: *const KeyMaterial) !void {
    try writeServerName(writer, options.host);
    try writeEmptyExtension(writer, 23);
    try writeRenegotiationInfo(writer);
    try writeU16ListExtension(writer, @intFromEnum(tls.ExtensionType.supported_groups), &.{
        @intFromEnum(tls.NamedGroup.x25519),
        @intFromEnum(tls.NamedGroup.secp256r1),
        @intFromEnum(tls.NamedGroup.secp384r1),
        0x0019,
        0x0100,
        0x0101,
    });
    try writeSupportedPoints(writer);
    try writeEmptyExtension(writer, 35); // session_ticket
    try writeAlpn(writer);
    try writeStatusRequest(writer);
    try writeDelegatedCredentials(writer);
    try writeKeyShare120(writer, key_material);
    try writeSupportedVersions(writer);
    try writeSignatureAlgorithms(writer);
    try writePskModes(writer);
    try writeRecordSizeLimit(writer);
}

fn writeCipherSuites(writer: *Io.Writer, suites: []const u16) !void {
    try writeU16(writer, suites.len * 2);
    for (suites) |suite| try writeU16(writer, suite);
}

fn writeServerName(writer: *Io.Writer, server_name: []const u8) !void {
    if (server_name.len == 0) return;
    const payload_len = 2 + 1 + 2 + server_name.len;
    try writeExtensionHeader(writer, @intFromEnum(tls.ExtensionType.server_name), payload_len);
    try writeU16(writer, 1 + 2 + server_name.len);
    try writer.writeByte(0);
    try writeU16(writer, server_name.len);
    try writer.writeAll(server_name);
}

fn writeRenegotiationInfo(writer: *Io.Writer) !void {
    try writeExtensionHeader(writer, 0xff01, 1);
    try writer.writeByte(0);
}

fn writeSupportedPoints(writer: *Io.Writer) !void {
    try writeExtensionHeader(writer, 11, 2);
    try writer.writeByte(1);
    try writer.writeByte(0);
}

fn writeAlpn(writer: *Io.Writer) !void {
    const h2 = "h2";
    const http11 = "http/1.1";
    const protocols_len = 1 + h2.len + 1 + http11.len;
    try writeExtensionHeader(writer, @intFromEnum(tls.ExtensionType.application_layer_protocol_negotiation), 2 + protocols_len);
    try writeU16(writer, protocols_len);
    try writer.writeByte(h2.len);
    try writer.writeAll(h2);
    try writer.writeByte(http11.len);
    try writer.writeAll(http11);
}

fn writeStatusRequest(writer: *Io.Writer) !void {
    try writeExtensionHeader(writer, @intFromEnum(tls.ExtensionType.status_request), 5);
    try writer.writeAll(&.{ 1, 0, 0, 0, 0 });
}

fn writeDelegatedCredentials(writer: *Io.Writer) !void {
    const schemes = [_]u16{ 0x0403, 0x0503, 0x0603, 0x0203 };
    try writeU16ListExtension(writer, 34, &schemes);
}

fn writeKeyShare148(writer: *Io.Writer, key_material: *const KeyMaterial) !void {
    const ml_kem_public = key_material.ml_kem768_kp.public_key.toBytes();
    const secp256r1_public = key_material.secp256r1_kp.public_key.toUncompressedSec1();
    const hybrid_len = ml_kem_public.len + key_material.x25519_kp.public_key.len;
    const entries_len = 2 + 2 + hybrid_len +
        2 + 2 + key_material.x25519_kp.public_key.len +
        2 + 2 + secp256r1_public.len;

    try writeExtensionHeader(writer, @intFromEnum(tls.ExtensionType.key_share), 2 + entries_len);
    try writeU16(writer, entries_len);
    try writeKeyShareEntryHeader(writer, @intFromEnum(tls.NamedGroup.x25519_ml_kem768), hybrid_len);
    try writer.writeAll(&ml_kem_public);
    try writer.writeAll(&key_material.x25519_kp.public_key);
    try writeKeyShareEntryHeader(writer, @intFromEnum(tls.NamedGroup.x25519), key_material.x25519_kp.public_key.len);
    try writer.writeAll(&key_material.x25519_kp.public_key);
    try writeKeyShareEntryHeader(writer, @intFromEnum(tls.NamedGroup.secp256r1), secp256r1_public.len);
    try writer.writeAll(&secp256r1_public);
}

fn writeKeyShare120(writer: *Io.Writer, key_material: *const KeyMaterial) !void {
    const secp256r1_public = key_material.secp256r1_kp.public_key.toUncompressedSec1();
    const entries_len = 2 + 2 + key_material.x25519_kp.public_key.len +
        2 + 2 + secp256r1_public.len;

    try writeExtensionHeader(writer, @intFromEnum(tls.ExtensionType.key_share), 2 + entries_len);
    try writeU16(writer, entries_len);
    try writeKeyShareEntryHeader(writer, @intFromEnum(tls.NamedGroup.x25519), key_material.x25519_kp.public_key.len);
    try writer.writeAll(&key_material.x25519_kp.public_key);
    try writeKeyShareEntryHeader(writer, @intFromEnum(tls.NamedGroup.secp256r1), secp256r1_public.len);
    try writer.writeAll(&secp256r1_public);
}

fn writeSupportedVersions(writer: *Io.Writer) !void {
    try writeExtensionHeader(writer, @intFromEnum(tls.ExtensionType.supported_versions), 5);
    try writer.writeByte(4);
    try writeU16(writer, @intFromEnum(tls.ProtocolVersion.tls_1_3));
    try writeU16(writer, @intFromEnum(tls.ProtocolVersion.tls_1_2));
}

fn writeSignatureAlgorithms(writer: *Io.Writer) !void {
    const schemes = [_]u16{
        0x0403, 0x0503, 0x0603,
        0x0804, 0x0805, 0x0806,
        0x0401, 0x0501, 0x0601,
        0x0203, 0x0201,
    };
    try writeU16ListExtension(writer, @intFromEnum(tls.ExtensionType.signature_algorithms), &schemes);
}

fn writePskModes(writer: *Io.Writer) !void {
    try writeExtensionHeader(writer, @intFromEnum(tls.ExtensionType.psk_key_exchange_modes), 2);
    try writer.writeByte(1);
    try writer.writeByte(@intFromEnum(tls.PskKeyExchangeMode.psk_dhe_ke));
}

fn writeRecordSizeLimit(writer: *Io.Writer) !void {
    try writeExtensionHeader(writer, 0x001c, 2);
    try writeU16(writer, 0x4001);
}

fn writeBoringPadding(writer: *Io.Writer) !void {
    const unpadded_len = writer.end;
    if (unpadded_len <= 0xff or unpadded_len >= 0x200) return;

    var padding_len = 0x200 - unpadded_len;
    if (padding_len >= 5) {
        padding_len -= 4;
    } else {
        padding_len = 1;
    }

    try writeExtensionHeader(writer, 21, padding_len);
    try writer.splatByteAll(0, padding_len);
}

fn writeCompressCertificate(writer: *Io.Writer, algorithms: []const u16) !void {
    try writeExtensionHeader(writer, 27, 1 + algorithms.len * 2);
    try writer.writeByte(@intCast(algorithms.len * 2));
    for (algorithms) |algorithm| try writeU16(writer, algorithm);
}

fn writeU16ListExtension(writer: *Io.Writer, extension_type: u16, values: []const u16) !void {
    try writeExtensionHeader(writer, extension_type, 2 + values.len * 2);
    try writeU16(writer, values.len * 2);
    for (values) |value| try writeU16(writer, value);
}

fn writeEmptyExtension(writer: *Io.Writer, extension_type: u16) !void {
    try writeExtensionHeader(writer, extension_type, 0);
}

fn writeExtensionHeader(writer: *Io.Writer, extension_type: u16, payload_len: usize) !void {
    try writeU16(writer, extension_type);
    try writeU16(writer, payload_len);
}

fn writeKeyShareEntryHeader(writer: *Io.Writer, group: u16, key_len: usize) !void {
    try writeU16(writer, group);
    try writeU16(writer, key_len);
}

fn writeU16(writer: *Io.Writer, value: anytype) !void {
    var bytes: [2]u8 = undefined;
    std.mem.writeInt(u16, &bytes, @intCast(value), .big);
    try writer.writeAll(&bytes);
}

fn patchU16(bytes: *[2]u8, value: u16) void {
    std.mem.writeInt(u16, bytes, value, .big);
}

fn patchU24(bytes: *[3]u8, value: u24) void {
    std.mem.writeInt(u24, bytes, value, .big);
}

test "builds Firefox 148 ClientHello shape" {
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*byte, i| byte.* = @intCast((i * 13 + 3) & 0xff);
    entropy[32..64].* = [_]u8{0} ** 32;
    var key_material = try KeyMaterial.init(entropy[64..240]);

    var out: [4096]u8 = undefined;
    const hello = try buildHandshake(&out, .{
        .host = "www.example.com",
        .entropy = &entropy,
        .fingerprint = .firefox,
    }, &key_material);

    try std.testing.expectEqual(@as(u8, @intFromEnum(tls.HandshakeType.client_hello)), hello[0]);
    try std.testing.expect(cipherSuitePresent(hello, 0xc02b));
    try std.testing.expect(cipherSuitePresent(hello, 0x1301));
    try std.testing.expect(cipherSuitePresent(hello, 0x1302));
    try std.testing.expect(cipherSuitePresent(hello, 0x1303));
    try std.testing.expect(extensionPresent(hello, @intFromEnum(tls.ExtensionType.key_share)));
    try std.testing.expect(extensionPresent(hello, @intFromEnum(tls.ExtensionType.supported_versions)));
    try std.testing.expect(supportedVersionPresent(hello, @intFromEnum(tls.ProtocolVersion.tls_1_3)));
    try std.testing.expect(supportedVersionPresent(hello, @intFromEnum(tls.ProtocolVersion.tls_1_2)));
    try std.testing.expect(!extensionPresent(hello, 0xfe0d));
}

test "chacha20-only policy preserves TLS versions without AES or ECH" {
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*byte, i| byte.* = @intCast((i * 19 + 5) & 0xff);
    entropy[32..64].* = [_]u8{0} ** 32;
    var key_material = try KeyMaterial.init(entropy[64..240]);

    var out: [4096]u8 = undefined;
    const hello = try buildHandshake(&out, .{
        .host = "www.example.com",
        .entropy = &entropy,
        .fingerprint = .firefox,
        .cipher_policy = .chacha20_only,
    }, &key_material);

    try std.testing.expect(cipherSuitePresent(hello, 0x1303));
    try std.testing.expect(cipherSuitePresent(hello, 0xcca9));
    try std.testing.expect(cipherSuitePresent(hello, 0xcca8));
    try std.testing.expect(!cipherSuitePresent(hello, 0x1301));
    try std.testing.expect(!cipherSuitePresent(hello, 0x1302));
    try std.testing.expect(supportedVersionPresent(hello, @intFromEnum(tls.ProtocolVersion.tls_1_3)));
    try std.testing.expect(supportedVersionPresent(hello, @intFromEnum(tls.ProtocolVersion.tls_1_2)));
    try std.testing.expect(!extensionPresent(hello, 0xfe0d));
}

test "session id is the only session-dependent ClientHello region" {
    var entropy: [entropy_len]u8 = undefined;
    for (&entropy, 0..) |*byte, i| byte.* = @intCast((i * 17 + 11) & 0xff);
    entropy[32..64].* = [_]u8{0} ** 32;
    const key_material = try KeyMaterial.init(entropy[64..240]);

    var first_buffer: [4096]u8 = undefined;
    const first = try buildHandshake(&first_buffer, .{
        .host = "www.example.com",
        .entropy = &entropy,
        .fingerprint = .firefox,
    }, &key_material);

    var changed_entropy = entropy;
    changed_entropy[32..64].* = [_]u8{0xaa} ** 32;
    var second_buffer: [4096]u8 = undefined;
    const second = try buildHandshake(&second_buffer, .{
        .host = "www.example.com",
        .entropy = &changed_entropy,
        .fingerprint = .firefox,
    }, &key_material);

    try std.testing.expectEqual(first.len, second.len);
    var normalized_second = try std.testing.allocator.dupe(u8, second);
    defer std.testing.allocator.free(normalized_second);
    normalized_second[39..71].* = [_]u8{0} ** 32;
    try std.testing.expectEqualSlices(u8, first, normalized_second);
}

fn cipherSuitePresent(hello: []const u8, suite: u16) bool {
    var index = clientHelloCipherSuitesOffset(hello);
    const suites_len = readU16(hello[index..][0..2]);
    index += 2;
    const end = index + suites_len;
    while (index < end) : (index += 2) {
        if (readU16(hello[index..][0..2]) == suite) return true;
    }
    return false;
}

fn extensionPresent(hello: []const u8, extension_type: u16) bool {
    var index = clientHelloExtensionsOffset(hello);
    const extensions_len = readU16(hello[index..][0..2]);
    index += 2;
    const end = index + extensions_len;
    while (index < end) {
        const current_type = readU16(hello[index..][0..2]);
        const payload_len = readU16(hello[index + 2 ..][0..2]);
        if (current_type == extension_type) return true;
        index += 4 + payload_len;
    }
    return false;
}

fn supportedVersionPresent(hello: []const u8, version: u16) bool {
    const payload = extensionPayload(hello, @intFromEnum(tls.ExtensionType.supported_versions)) orelse return false;
    if (payload.len < 1) return false;
    var index: usize = 1;
    const end = 1 + payload[0];
    if (end > payload.len) return false;
    while (index < end) : (index += 2) {
        if (readU16(payload[index..][0..2]) == version) return true;
    }
    return false;
}

fn extensionPayload(hello: []const u8, extension_type: u16) ?[]const u8 {
    var index = clientHelloExtensionsOffset(hello);
    const extensions_len = readU16(hello[index..][0..2]);
    index += 2;
    const end = index + extensions_len;
    while (index < end) {
        const current_type = readU16(hello[index..][0..2]);
        const payload_len = readU16(hello[index + 2 ..][0..2]);
        const payload = hello[index + 4 ..][0..payload_len];
        if (current_type == extension_type) return payload;
        index += 4 + payload_len;
    }
    return null;
}

fn clientHelloCipherSuitesOffset(hello: []const u8) usize {
    var index: usize = 4 + 2 + 32;
    const session_id_len = hello[index];
    index += 1 + session_id_len;
    return index;
}

fn clientHelloExtensionsOffset(hello: []const u8) usize {
    var index = clientHelloCipherSuitesOffset(hello);
    index += 2 + readU16(hello[index..][0..2]);
    const compression_methods_len = hello[index];
    index += 1 + compression_methods_len;
    return index;
}

fn readU16(bytes: *const [2]u8) u16 {
    return std.mem.readInt(u16, bytes, .big);
}
