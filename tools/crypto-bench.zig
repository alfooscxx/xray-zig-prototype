const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const block_len = 16 * 1024;
const total_len = 32 * 1024 * 1024;

var plaintext: [block_len]u8 = undefined;
var ciphertext: [block_len]u8 = undefined;
var decrypted: [block_len]u8 = undefined;

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var stdout_buffer: [512]u8 = undefined;
    var stdout_writer = std.Io.File.stdout().writer(io, &stdout_buffer);
    const stdout = &stdout_writer.interface;

    for (&plaintext, 0..) |*byte, index| byte.* = @truncate(index *% 131 +% 17);

    try stdout.print("aes_hardware={} block_bytes={d} total_bytes={d}\n", .{
        std.crypto.core.aes.has_hardware_support,
        block_len,
        total_len,
    });
    try bench(Aes128Gcm, "aes-128-gcm", io, stdout);
    try bench(ChaCha20Poly1305, "chacha20-poly1305", io, stdout);
    try stdout.flush();
}

fn bench(comptime Aead: type, name: []const u8, io: std.Io, stdout: *std.Io.Writer) !void {
    const key: [Aead.key_length]u8 = @splat(0x42);
    const nonce: [Aead.nonce_length]u8 = @splat(0x24);
    var tag: [Aead.tag_length]u8 = undefined;

    const started = std.Io.Clock.awake.now(io).nanoseconds;
    var processed: usize = 0;
    while (processed < total_len) : (processed += block_len) {
        Aead.encrypt(&ciphertext, &tag, &plaintext, "", nonce, key);
        try Aead.decrypt(&decrypted, &ciphertext, tag, "", nonce, key);
    }
    const elapsed_ns = std.Io.Clock.awake.now(io).nanoseconds - started;

    std.mem.doNotOptimizeAway(&ciphertext);
    std.mem.doNotOptimizeAway(&decrypted);
    const bytes: f64 = @floatFromInt(total_len * 2);
    const seconds: f64 = @as(f64, @floatFromInt(elapsed_ns)) / std.time.ns_per_s;
    const mib_per_second = bytes / seconds / (1024 * 1024);
    try stdout.print("{s} {d:.2} MiB/s\n", .{ name, mib_per_second });
}
