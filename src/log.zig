const builtin = @import("builtin");
const std = @import("std");
const build_options = @import("build_options");

pub const Level = enum(u8) {
    trace,
    debug,
    info,
    warn,
    err,
};

pub const minimum_level: Level = if (build_options.trace)
    .trace
else if (builtin.mode == .Debug)
    .debug
else
    .info;

pub inline fn write(comptime level: Level, comptime format: []const u8, args: anytype) void {
    if (comptime @intFromEnum(level) >= @intFromEnum(minimum_level)) {
        std.debug.print(format, args);
    }
}

pub inline fn trace(comptime format: []const u8, args: anytype) void {
    write(.trace, format, args);
}

pub inline fn debug(comptime format: []const u8, args: anytype) void {
    write(.debug, format, args);
}

pub inline fn info(comptime format: []const u8, args: anytype) void {
    write(.info, format, args);
}

pub inline fn warn(comptime format: []const u8, args: anytype) void {
    write(.warn, format, args);
}

pub inline fn err(comptime format: []const u8, args: anytype) void {
    write(.err, format, args);
}

test "release logging levels remain ordered" {
    try std.testing.expect(@intFromEnum(Level.trace) < @intFromEnum(Level.err));
}
