const builtin = @import("builtin");
const std = @import("std");

pub fn setThreadName(name: [:0]const u8) void {
    if (builtin.os.tag != .linux or name.len > std.Thread.max_name_len) return;
    _ = std.posix.prctl(.SET_NAME, .{@intFromPtr(name.ptr)}) catch {};
}

pub fn setRawReactorCount(active_count: usize) void {
    var buffer: [std.Thread.max_name_len + 1]u8 = undefined;
    const name = std.fmt.bufPrintZ(&buffer, "xz-raw-{d}", .{active_count}) catch return;
    setThreadName(name);
}

test "raw reactor thread name fits Linux limit" {
    var buffer: [std.Thread.max_name_len + 1]u8 = undefined;
    const name = try std.fmt.bufPrintZ(&buffer, "xz-raw-{d}", .{999_999});
    try std.testing.expect(name.len <= std.Thread.max_name_len);
}
