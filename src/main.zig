const std = @import("std");
const Io = std.Io;

const xray = @import("xray_zig");

const max_config_bytes = 16 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);

    var threaded: Io.Threaded = .init(init.gpa, .{
        .stack_size = 1024 * 1024,
        .concurrent_limit = .limited(128),
    });
    defer threaded.deinit();
    const io = threaded.io();

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_file_writer: Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const stdout = &stdout_file_writer.interface;
    defer stdout.flush() catch {};

    var stderr_buffer: [4096]u8 = undefined;
    var stderr_file_writer: Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const stderr = &stderr_file_writer.interface;
    defer stderr.flush() catch {};

    if (args.len < 2) {
        try usage(stderr);
        std.process.exit(2);
    }

    const command = args[1];
    if (std.mem.eql(u8, command, "version")) {
        try stdout.print("xray-zig mvp 0.0.0\n", .{});
        return;
    }

    const config_path = findConfigPath(args[2..]) orelse {
        try stderr.print("missing -config <path>\n\n", .{});
        try usage(stderr);
        std.process.exit(2);
    };

    var cfg = try loadConfig(arena, io, config_path);
    defer cfg.deinit();

    if (std.mem.eql(u8, command, "check")) {
        try xray.core.validate(&cfg);
        try printSummary(stdout, &cfg);
        return;
    }

    if (std.mem.eql(u8, command, "run")) {
        try xray.core.validate(&cfg);
        var runtime: xray.core.Runtime = .{ .cfg = &cfg, .allocator = arena };
        try runtime.run(io, stdout);
        return;
    }

    try stderr.print("unknown command: {s}\n\n", .{command});
    try usage(stderr);
    std.process.exit(2);
}

fn usage(writer: *Io.Writer) !void {
    try writer.writeAll(
        \\usage:
        \\  xray-zig check -config <path>
        \\  xray-zig run -config <path>
        \\  xray-zig version
        \\
    );
}

fn findConfigPath(args: []const []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "-config") or
            std.mem.eql(u8, args[i], "--config") or
            std.mem.eql(u8, args[i], "-c"))
        {
            if (i + 1 >= args.len) return null;
            return args[i + 1];
        }
    }
    return null;
}

fn loadConfig(allocator: std.mem.Allocator, io: Io, path: []const u8) !xray.config.Config {
    const bytes = try Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_config_bytes));
    return xray.config.parse(allocator, bytes);
}

fn printSummary(writer: *Io.Writer, cfg: *const xray.config.Config) !void {
    try writer.print("config ok: {d} inbound(s), {d} outbound(s)\n", .{
        cfg.inbounds.len,
        cfg.outbounds.len,
    });
    for (cfg.inbounds) |inbound| {
        try writer.print("inbound {s}: {s} on {s}:{d}\n", .{
            inbound.tag orelse "-",
            inbound.protocol,
            inbound.listen,
            inbound.port,
        });
    }
    for (cfg.outbounds) |outbound| {
        try writer.print("outbound {s}: {s}\n", .{
            outbound.tag orelse "-",
            outbound.protocol,
        });
    }
}
