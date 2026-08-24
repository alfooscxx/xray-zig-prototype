const std = @import("std");
const Io = std.Io;

const xray = @import("xray_zig");

const max_config_bytes = 16 * 1024 * 1024;
const worker_stack_size = 1024 * 1024;
const default_memory_budget_mib = 512;
const raw_connections_per_worker = 5;
const estimated_raw_connection_kib = 112;
const estimated_worker_kib = estimated_raw_connection_kib * raw_connections_per_worker;
const max_memory_budget_mib = 4096;
const max_requested_capacity = 1_000_000;
const default_reality_handshake_limit = 32;

const RuntimeCapacity = struct {
    memory_budget_mib: usize,
    worker_limit: usize,
    raw_connection_limit: usize,
    reality_handshake_limit: usize,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    const capacity = try runtimeCapacity(init.environ_map);

    std.process.raiseFileDescriptorLimit();

    var threaded: Io.Threaded = .init(init.gpa, .{
        .stack_size = worker_stack_size,
        .concurrent_limit = .limited(capacity.worker_limit),
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
        try stdout.print("xray-zig {s}\n", .{xray.version});
        return;
    }

    if (std.mem.eql(u8, command, "ctl")) {
        try runControlClient(args[2..], init.environ_map, io, stdout, stderr);
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

    if (std.mem.eql(u8, command, "fakedns-unpin")) {
        try xray.core.validate(&cfg);
        const fake_dns_cfg = if (cfg.dns) |dns_cfg|
            dns_cfg.fake_dns orelse return error.MissingFakeDnsConfig
        else
            return error.MissingFakeDnsConfig;
        for (cfg.inbounds) |inbound| {
            if (!std.mem.eql(u8, inbound.protocol, "sk_lookup")) continue;
            try xray.proxy.sk_lookup.bpf.unpinPersistent(inbound.sk_lookup.?, fake_dns_cfg, io);
            try stdout.print("FakeDNS BPF pins removed\n", .{});
            return;
        }
        return error.MissingSkLookupSettings;
    }

    if (std.mem.eql(u8, command, "run")) {
        try xray.core.validate(&cfg);
        try stdout.print(
            "runtime capacity: memory_budget_mib={d} heavy_workers={d} io_uring_raw_connections={d} reality_handshakes={d}\n",
            .{
                capacity.memory_budget_mib,
                capacity.worker_limit,
                capacity.raw_connection_limit,
                capacity.reality_handshake_limit,
            },
        );
        try stdout.flush();
        // Runtime-owned connection state must support individual frees. The
        // process arena is reserved for configuration and CLI lifetime data.
        var runtime: xray.core.Runtime = .{
            .cfg = &cfg,
            .allocator = init.gpa,
            .raw_connection_limit = capacity.raw_connection_limit,
            .reality_handshake_slots = .{ .permits = capacity.reality_handshake_limit },
            // Raw connections are page-sized, long-lived allocations. Freeing
            // them should unmap their storage instead of retaining it in the
            // ReleaseFast SMP allocator's caches.
            .reactor_allocator = std.heap.page_allocator,
            .monitoring_enabled = monitoringEnabled(init.environ_map),
            .control_socket_path = init.environ_map.get("XRAY_ZIG_CONTROL_SOCKET") orelse xray.control.default_socket_path,
        };
        try runtime.run(io, stdout);
        return;
    }

    try stderr.print("unknown command: {s}\n\n", .{command});
    try usage(stderr);
    std.process.exit(2);
}

fn runtimeCapacity(environ: *const std.process.Environ.Map) !RuntimeCapacity {
    const memory_budget_mib = try parseEnvironmentLimit(
        environ,
        "XRAY_ZIG_MEMORY_BUDGET_MIB",
        default_memory_budget_mib,
        max_memory_budget_mib,
    );
    const requested_workers = try parseEnvironmentLimitOptional(
        environ,
        "XRAY_ZIG_WORKER_LIMIT",
        max_requested_capacity,
    );
    const requested_raw = try parseEnvironmentLimitOptional(
        environ,
        "XRAY_ZIG_RAW_CONNECTION_LIMIT",
        max_requested_capacity,
    );
    const reality_handshake_limit = try parseEnvironmentLimit(
        environ,
        "XRAY_ZIG_REALITY_HANDSHAKE_LIMIT",
        default_reality_handshake_limit,
        max_requested_capacity,
    );

    if (requested_workers == null and requested_raw == null) {
        var capacity = try calculateAutomaticCapacity(memory_budget_mib);
        capacity.reality_handshake_limit = reality_handshake_limit;
        return capacity;
    }

    if (requested_workers) |workers| {
        const raw_connections = requested_raw orelse std.math.mul(
            usize,
            workers,
            raw_connections_per_worker,
        ) catch return error.InvalidRuntimeCapacity;
        var capacity = try calculateCapacity(memory_budget_mib, workers, raw_connections);
        capacity.reality_handshake_limit = reality_handshake_limit;
        return capacity;
    }

    const raw_connections = requested_raw.?;
    const budget_kib = std.math.mul(usize, memory_budget_mib, 1024) catch
        return error.InvalidRuntimeCapacity;
    const raw_kib = std.math.mul(usize, raw_connections, estimated_raw_connection_kib) catch
        return error.InvalidRuntimeCapacity;
    const requested_from_remainder = if (raw_kib < budget_kib)
        @max(@as(usize, 1), (budget_kib - raw_kib) / estimated_worker_kib)
    else
        1;
    var capacity = try calculateCapacity(memory_budget_mib, requested_from_remainder, raw_connections);
    capacity.reality_handshake_limit = reality_handshake_limit;
    return capacity;
}

fn parseEnvironmentLimit(
    environ: *const std.process.Environ.Map,
    name: []const u8,
    default: usize,
    maximum: usize,
) !usize {
    const value = environ.get(name) orelse return default;
    const parsed = std.fmt.parseUnsigned(usize, value, 10) catch
        return error.InvalidRuntimeCapacity;
    if (parsed == 0 or parsed > maximum) return error.InvalidRuntimeCapacity;
    return parsed;
}

fn parseEnvironmentLimitOptional(
    environ: *const std.process.Environ.Map,
    name: []const u8,
    maximum: usize,
) !?usize {
    const value = environ.get(name) orelse return null;
    const parsed = std.fmt.parseUnsigned(usize, value, 10) catch
        return error.InvalidRuntimeCapacity;
    if (parsed == 0 or parsed > maximum) return error.InvalidRuntimeCapacity;
    return parsed;
}

fn calculateAutomaticCapacity(memory_budget_mib: usize) !RuntimeCapacity {
    if (memory_budget_mib == 0) return error.InvalidRuntimeCapacity;
    const budget_kib = std.math.mul(usize, memory_budget_mib, 1024) catch
        return error.InvalidRuntimeCapacity;
    const raw_bundle_kib = std.math.mul(
        usize,
        raw_connections_per_worker,
        estimated_raw_connection_kib,
    ) catch return error.InvalidRuntimeCapacity;
    const bundle_kib = std.math.add(usize, estimated_worker_kib, raw_bundle_kib) catch
        return error.InvalidRuntimeCapacity;
    const workers = budget_kib / bundle_kib;
    if (workers == 0) return error.MemoryBudgetTooSmall;
    const raw_connections = @min(
        std.math.mul(usize, workers, raw_connections_per_worker) catch
            return error.InvalidRuntimeCapacity,
        xray.net.reactor.max_connections_per_ring,
    );
    return .{
        .memory_budget_mib = memory_budget_mib,
        .worker_limit = workers,
        .raw_connection_limit = raw_connections,
        .reality_handshake_limit = default_reality_handshake_limit,
    };
}

fn calculateCapacity(
    memory_budget_mib: usize,
    requested_workers: usize,
    requested_raw: usize,
) !RuntimeCapacity {
    if (memory_budget_mib == 0 or requested_workers == 0 or requested_raw == 0)
        return error.InvalidRuntimeCapacity;
    if (requested_raw > xray.net.reactor.max_connections_per_ring)
        return error.RawReactorCapacityTooLarge;

    const budget_kib = std.math.mul(usize, memory_budget_mib, 1024) catch
        return error.InvalidRuntimeCapacity;
    const budget_units = budget_kib / estimated_raw_connection_kib;
    if (budget_units < raw_connections_per_worker + 1)
        return error.MemoryBudgetTooSmall;

    const requested_units =
        @as(u128, requested_workers) * raw_connections_per_worker + requested_raw;
    if (requested_units <= budget_units) return .{
        .memory_budget_mib = memory_budget_mib,
        .worker_limit = requested_workers,
        .raw_connection_limit = requested_raw,
        .reality_handshake_limit = default_reality_handshake_limit,
    };

    var workers: usize = @intCast(
        @as(u128, requested_workers) * budget_units / requested_units,
    );
    var raw_connections: usize = @intCast(
        @as(u128, requested_raw) * budget_units / requested_units,
    );
    workers = @max(workers, 1);
    raw_connections = @max(raw_connections, 1);

    while (workers * estimated_worker_kib +
        raw_connections * estimated_raw_connection_kib > budget_kib)
    {
        if (raw_connections > 1) {
            raw_connections -= 1;
        } else if (workers > 1) {
            workers -= 1;
        } else {
            return error.MemoryBudgetTooSmall;
        }
    }

    return .{
        .memory_budget_mib = memory_budget_mib,
        .worker_limit = workers,
        .raw_connection_limit = raw_connections,
        .reality_handshake_limit = default_reality_handshake_limit,
    };
}

fn usage(writer: *Io.Writer) !void {
    try writer.writeAll(
        \\usage:
        \\  xray-zig check -config <path>
        \\  xray-zig run -config <path>
        \\  xray-zig fakedns-unpin -config <path>
        \\  xray-zig ctl status|top|metrics|bpf|events [--limit N] [--socket <path>]
        \\  xray-zig version
        \\
    );
}

fn monitoringEnabled(environ: *const std.process.Environ.Map) bool {
    const value = environ.get("XRAY_ZIG_MONITORING") orelse return true;
    return !std.mem.eql(u8, value, "0") and
        !std.ascii.eqlIgnoreCase(value, "false") and
        !std.ascii.eqlIgnoreCase(value, "off");
}

fn runControlClient(
    args: []const []const u8,
    environ: *const std.process.Environ.Map,
    io: Io,
    stdout: *Io.Writer,
    stderr: *Io.Writer,
) !void {
    if (args.len == 0) {
        try usage(stderr);
        std.process.exit(2);
    }
    const operation = args[0];
    var socket_path = environ.get("XRAY_ZIG_CONTROL_SOCKET") orelse xray.control.default_socket_path;
    var limit: ?usize = null;
    var index: usize = 1;
    while (index < args.len) {
        if (std.mem.eql(u8, args[index], "--socket")) {
            if (index + 1 >= args.len) return error.MissingControlSocketPath;
            socket_path = args[index + 1];
            index += 2;
            continue;
        }
        if (std.mem.eql(u8, args[index], "--limit")) {
            if (index + 1 >= args.len) return error.MissingEventLimit;
            limit = try std.fmt.parseUnsigned(usize, args[index + 1], 10);
            index += 2;
            continue;
        }
        return error.UnknownControlOption;
    }

    var request_buffer: [xray.control.max_request_bytes]u8 = undefined;
    const request = if (std.mem.eql(u8, operation, "events"))
        try std.fmt.bufPrint(&request_buffer, "events {d}", .{limit orelse 50})
    else blk: {
        if (limit != null) return error.EventLimitRequiresEvents;
        break :blk try std.fmt.bufPrint(&request_buffer, "{s}", .{operation});
    };
    try xray.control.runClient(io, socket_path, request, stdout);
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
        if (std.mem.eql(u8, inbound.protocol, "tun")) {
            const settings = inbound.tun.?;
            try writer.print("inbound {s}: tun device {s} mtu {d}\n", .{
                inbound.tag orelse "-",
                settings.name,
                settings.mtu,
            });
            continue;
        }
        if (std.mem.eql(u8, inbound.protocol, "sk_lookup")) {
            const settings = inbound.sk_lookup.?;
            try writer.print("inbound {s}: sk_lookup TCP on {s}:{d} and [{s}]:{d}, map entries {d}\n", .{
                inbound.tag orelse "-",
                settings.listen4,
                settings.port4,
                settings.listen6,
                settings.port6,
                settings.max_map_entries,
            });
            if (settings.fake_dns_persistence) |persistence|
                try writer.print("  persistent FakeDNS BPF maps: {s}\n", .{persistence.pin_directory});
            if (settings.sockhash_offload) |offload| {
                try writer.print("  required TCP SOCKHASH offload: max flows {d}, idle timeout {d}s\n", .{
                    offload.max_flows,
                    offload.idle_timeout_seconds,
                });
            }
            if (settings.transparent_intercept) |transparent| {
                try writer.print("  transparent TCP literals: ingress {s}, {d} excluded CIDR(s), {d} proxy server address(es)\n", .{
                    transparent.ingress_interface,
                    transparent.excluded_ips.len,
                    transparent.proxy_server_ips.len,
                });
            }
            continue;
        }
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

test "automatic runtime capacity is derived from the memory budget" {
    const capacity = try calculateAutomaticCapacity(70);
    try std.testing.expectEqual(@as(usize, 70), capacity.memory_budget_mib);
    try std.testing.expectEqual(@as(usize, 64), capacity.worker_limit);
    try std.testing.expectEqual(@as(usize, 320), capacity.raw_connection_limit);
}

test "automatic 512 MiB capacity has no fixed worker ceiling" {
    const capacity = try calculateAutomaticCapacity(512);
    try std.testing.expectEqual(@as(usize, 512), capacity.memory_budget_mib);
    try std.testing.expectEqual(@as(usize, 468), capacity.worker_limit);
    try std.testing.expectEqual(@as(usize, 2340), capacity.raw_connection_limit);
    try std.testing.expectEqual(@as(usize, 32), capacity.reality_handshake_limit);
}

test "REALITY handshake capacity is configurable through the environment" {
    var environ: std.process.Environ.Map = .init(std.testing.allocator);
    defer environ.deinit();
    try environ.put("XRAY_ZIG_REALITY_HANDSHAKE_LIMIT", "64");

    const capacity = try runtimeCapacity(&environ);
    try std.testing.expectEqual(@as(usize, 64), capacity.reality_handshake_limit);
}

test "REALITY handshake capacity rejects zero" {
    var environ: std.process.Environ.Map = .init(std.testing.allocator);
    defer environ.deinit();
    try environ.put("XRAY_ZIG_REALITY_HANDSHAKE_LIMIT", "0");

    try std.testing.expectError(error.InvalidRuntimeCapacity, runtimeCapacity(&environ));
}

test "explicit runtime requests are proportionally bounded by memory" {
    const capacity = try calculateCapacity(70, 128, 640);
    try std.testing.expectEqual(@as(usize, 70), capacity.memory_budget_mib);
    try std.testing.expectEqual(@as(usize, 64), capacity.worker_limit);
    try std.testing.expectEqual(@as(usize, 320), capacity.raw_connection_limit);
}

test "runtime capacity preserves values already inside the memory budget" {
    const capacity = try calculateCapacity(70, 80, 240);
    try std.testing.expectEqual(@as(usize, 80), capacity.worker_limit);
    try std.testing.expectEqual(@as(usize, 240), capacity.raw_connection_limit);
}

test "runtime capacity rejects a zero memory budget" {
    try std.testing.expectError(
        error.InvalidRuntimeCapacity,
        calculateCapacity(0, 1, 1),
    );
}

test "runtime capacity bounds one io_uring shard" {
    try std.testing.expectError(
        error.RawReactorCapacityTooLarge,
        calculateCapacity(4096, 128, xray.net.reactor.max_connections_per_ring + 1),
    );
    const automatic = try calculateAutomaticCapacity(4096);
    try std.testing.expectEqual(xray.net.reactor.max_connections_per_ring, automatic.raw_connection_limit);
}
