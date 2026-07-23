const std = @import("std");

pub const CipherPolicy = enum {
    firefox,
    chacha20_only,
};

pub const default_policy: CipherPolicy = .firefox;

pub fn parse(value: ?[]const u8) !CipherPolicy {
    const text = value orelse return default_policy;
    if (std.ascii.eqlIgnoreCase(text, "firefox")) return .firefox;
    if (std.ascii.eqlIgnoreCase(text, "chacha20-only")) return .chacha20_only;
    return error.UnsupportedTlsCipherPolicy;
}

test "parses explicit TLS cipher policies" {
    try std.testing.expectEqual(CipherPolicy.firefox, try parse(null));
    try std.testing.expectEqual(CipherPolicy.firefox, try parse("Firefox"));
    try std.testing.expectEqual(CipherPolicy.chacha20_only, try parse("chacha20-only"));
    try std.testing.expectError(error.UnsupportedTlsCipherPolicy, parse("aes"));
}
