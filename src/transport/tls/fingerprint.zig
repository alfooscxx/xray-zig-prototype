const std = @import("std");

pub const default_fingerprint: Fingerprint = .firefox;

pub const Fingerprint = enum {
    firefox,
    chrome,
    safari,
    ios,
    edge,
    qq,
    hellofirefox_105,
    hellofirefox_120,
    hellofirefox_148,
    hellochrome_120,
    hellochrome_131,
    hellochrome_133,
    helloios_13,
    helloios_14,
    helloedge_106,
    hellosafari_26_3,
    helloqq_11_1,

    pub fn name(self: Fingerprint) []const u8 {
        return switch (self) {
            .firefox => "firefox",
            .chrome => "chrome",
            .safari => "safari",
            .ios => "ios",
            .edge => "edge",
            .qq => "qq",
            .hellofirefox_105 => "hellofirefox_105",
            .hellofirefox_120 => "hellofirefox_120",
            .hellofirefox_148 => "hellofirefox_148",
            .hellochrome_120 => "hellochrome_120",
            .hellochrome_131 => "hellochrome_131",
            .hellochrome_133 => "hellochrome_133",
            .helloios_13 => "helloios_13",
            .helloios_14 => "helloios_14",
            .helloedge_106 => "helloedge_106",
            .hellosafari_26_3 => "hellosafari_26_3",
            .helloqq_11_1 => "helloqq_11_1",
        };
    }

    pub fn isFirefoxLike(self: Fingerprint) bool {
        return switch (self) {
            .firefox,
            .hellofirefox_105,
            .hellofirefox_120,
            .hellofirefox_148,
            => true,
            else => false,
        };
    }
};

pub fn parse(value: ?[]const u8) !Fingerprint {
    const text = value orelse return default_fingerprint;
    inline for (@typeInfo(Fingerprint).@"enum".fields) |field| {
        if (std.ascii.eqlIgnoreCase(text, field.name)) {
            return @enumFromInt(field.value);
        }
    }
    return error.UnsupportedTlsFingerprint;
}

test "defaults to Firefox" {
    try std.testing.expectEqual(Fingerprint.firefox, try parse(null));
}

test "parses browser fingerprints case-insensitively" {
    try std.testing.expectEqual(Fingerprint.firefox, try parse("Firefox"));
    try std.testing.expectEqual(Fingerprint.hellofirefox_105, try parse("HelloFirefox_105"));
    try std.testing.expectEqual(Fingerprint.hellochrome_133, try parse("HelloChrome_133"));
}

test "rejects non-browser or unsafe fingerprints" {
    try std.testing.expectError(error.UnsupportedTlsFingerprint, parse("unsafe"));
    try std.testing.expectError(error.UnsupportedTlsFingerprint, parse("hellogolang"));
    try std.testing.expectError(error.UnsupportedTlsFingerprint, parse("random"));
    try std.testing.expectError(error.UnsupportedTlsFingerprint, parse("randomized"));
}
