const std = @import("std");
const linux = std.os.linux;
const BPF = linux.BPF;
const fd_t = std.posix.fd_t;

const listen_port: u16 = 19090;
const target_port: u16 = 19091;
const sk_pass = 1;
const af_inet = 2;
const ipproto_tcp = 6;
const max_cfg_blocks = 512;

const Case = enum { direct, chain, tail_call, cfg_load };
const Format = enum { json, tsv };

const Program = struct {
    instructions: [2048]BPF.Insn = undefined,
    len: usize = 0,

    fn emit(self: *Program, instruction: BPF.Insn) usize {
        std.debug.assert(self.len < self.instructions.len);
        const at = self.len;
        self.instructions[at] = instruction;
        self.len += 1;
        return at;
    }

    fn patch(self: *Program, at: usize, target: usize) void {
        self.instructions[at].off = @intCast(@as(isize, @intCast(target)) - @as(isize, @intCast(at)) - 1);
    }

    fn slice(self: *const Program) []const BPF.Insn {
        return self.instructions[0..self.len];
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 2) return usage();
    if (std.mem.eql(u8, args[1], "client")) {
        if (args.len != 3) return usage();
        return runClient(args[2]);
    }
    if (!std.mem.eql(u8, args[1], "server") or args.len != 6) return usage();
    const case = std.meta.stringToEnum(Case, args[2]) orelse return error.InvalidCase;
    const blocks = try std.fmt.parseUnsigned(u16, args[3], 10);
    if (blocks > max_cfg_blocks or (case != .cfg_load and blocks != 0)) return error.InvalidCfgBlockCount;
    const format = std.meta.stringToEnum(Format, args[4]) orelse return error.InvalidFormat;
    const transparent = if (std.mem.eql(u8, args[5], "1")) true else if (std.mem.eql(u8, args[5], "0")) false else return error.InvalidTransparentFlag;
    try runServer(case, blocks, format, transparent);
}

fn usage() error{InvalidArguments} {
    std.debug.print("usage: sk-lookup-conformance server direct|chain|tail_call|cfg_load CFG_BLOCKS json|tsv TRANSPARENT_0_OR_1\n" ++
        "       sk-lookup-conformance client ADDRESS\n", .{});
    return error.InvalidArguments;
}

fn runServer(case: Case, blocks: u16, format: Format, transparent: bool) !void {
    const listener = try openListener(transparent);
    defer closeFd(listener);
    const sockets = try createMap(.sockmap, 4, 4, 1, "skc_socks");
    defer closeFd(sockets);
    const counters = try createMap(.array, 4, 8, 3, "skc_count");
    defer closeFd(counters);
    const key: u32 = 0;
    try update(sockets, std.mem.asBytes(&key), std.mem.asBytes(&listener));

    var selector = selectorProgram(sockets, counters, blocks);
    var observer = observerProgram(counters);
    var dispatcher: Program = .{};
    var programs: fd_t = -1;
    var selector_fd: fd_t = -1;
    var observer_fd: fd_t = -1;
    var dispatcher_fd: fd_t = -1;
    var first_link_fd: fd_t = -1;
    var second_link_fd: fd_t = -1;
    defer if (programs >= 0) closeFd(programs);
    defer if (selector_fd >= 0) closeFd(selector_fd);
    defer if (observer_fd >= 0) closeFd(observer_fd);
    defer if (dispatcher_fd >= 0) closeFd(dispatcher_fd);
    defer if (second_link_fd >= 0) closeFd(second_link_fd);
    defer if (first_link_fd >= 0) closeFd(first_link_fd);

    selector_fd = try loadProgram(selector.slice(), "skc_select");
    const namespace = try openNetns();
    defer closeFd(namespace);
    switch (case) {
        .direct, .cfg_load => first_link_fd = try attach(selector_fd, namespace),
        .chain => {
            observer_fd = try loadProgram(observer.slice(), "skc_observe");
            first_link_fd = try attach(selector_fd, namespace);
            second_link_fd = try attach(observer_fd, namespace);
        },
        .tail_call => {
            programs = try createMap(.prog_array, 4, 4, 1, "skc_progs");
            try update(programs, std.mem.asBytes(&key), std.mem.asBytes(&selector_fd));
            dispatcher = dispatcherProgram(programs);
            dispatcher_fd = try loadProgram(dispatcher.slice(), "skc_dispatch");
            first_link_fd = try attach(dispatcher_fd, namespace);
        },
    }

    std.debug.print("READY\n", .{});
    const accepted = acceptOne(listener) catch |err| {
        try emitResult(format, case, false, false, counters, totalInstructions(case, &selector, &observer, &dispatcher));
        return err;
    };
    defer closeFd(accepted);
    var byte: [1]u8 = undefined;
    const got = linux.recvfrom(accepted, &byte, 1, 0, null, null);
    const accepted_ok = linux.errno(got) == .SUCCESS and got == 1;
    var echo_ok = false;
    if (accepted_ok) {
        const sent = linux.sendto(accepted, &byte, 1, 0, null, 0);
        echo_ok = linux.errno(sent) == .SUCCESS and sent == 1;
    }
    try emitResult(format, case, accepted_ok, echo_ok, counters, totalInstructions(case, &selector, &observer, &dispatcher));
    if (!accepted_ok or !echo_ok) return error.EchoFailed;
}

fn runClient(address_text: []const u8) !void {
    var address = linux.sockaddr.in{
        .port = std.mem.nativeToBig(u16, target_port),
        .addr = 0,
    };
    var parsed: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, address_text, '.');
    for (&parsed) |*part| part.* = try std.fmt.parseUnsigned(u8, parts.next() orelse return error.InvalidAddress, 10);
    if (parts.next() != null) return error.InvalidAddress;
    @memcpy(std.mem.asBytes(&address.addr), &parsed);
    const fd = try socket();
    defer closeFd(fd);
    const rc = linux.connect(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)));
    if (linux.errno(rc) != .SUCCESS) return error.ConnectFailed;
    const payload = [_]u8{'C'};
    if (linux.errno(linux.sendto(fd, &payload, 1, 0, null, 0)) != .SUCCESS) return error.SendFailed;
    var echoed: [1]u8 = undefined;
    const got = linux.recvfrom(fd, &echoed, 1, 0, null, null);
    if (linux.errno(got) != .SUCCESS or got != 1 or echoed[0] != payload[0]) return error.EchoMismatch;
}

fn selectorProgram(sockets: fd_t, counters: fd_t, cfg_blocks: u16) Program {
    var p: Program = .{};
    _ = p.emit(BPF.Insn.mov(.r6, .r1));
    if (cfg_blocks != 0) {
        _ = p.emit(BPF.Insn.ldx(.word, .r0, .r6, 8)); // family
        const skip = p.emit(BPF.Insn.jeq(.r0, af_inet, 0));
        for (0..cfg_blocks) |_| {
            _ = p.emit(BPF.Insn.ldx(.word, .r0, .r6, 12)); // verifier-reachable, not run for IPv4
            _ = p.emit(BPF.Insn.jeq(.r0, ipproto_tcp, 1));
            _ = p.emit(BPF.Insn.mov(.r0, .r0));
        }
        p.patch(skip, p.len);
    }
    _ = p.emit(BPF.Insn.st(.word, .r10, -4, 0));
    _ = p.emit(BPF.Insn.ld_map_fd1(.r1, sockets));
    _ = p.emit(BPF.Insn.ld_map_fd2(sockets));
    _ = p.emit(BPF.Insn.mov(.r2, .r10));
    _ = p.emit(BPF.Insn.add(.r2, -4));
    _ = p.emit(BPF.Insn.call(.map_lookup_elem));
    const missing = p.emit(BPF.Insn.jeq(.r0, 0, 0));
    _ = p.emit(BPF.Insn.mov(.r7, .r0));
    _ = p.emit(BPF.Insn.mov(.r1, .r6));
    _ = p.emit(BPF.Insn.mov(.r2, .r7));
    _ = p.emit(BPF.Insn.mov(.r3, 0));
    _ = p.emit(BPF.Insn.call(.sk_assign));
    _ = p.emit(BPF.Insn.mov(.r8, .r0));
    _ = p.emit(BPF.Insn.mov(.r1, .r7));
    _ = p.emit(BPF.Insn.call(.sk_release));
    const error_counter = p.emit(BPF.Insn.jne(.r8, 0, 0));
    emitCounter(&p, counters, 0);
    const done = p.emit(BPF.Insn.ja(0));
    const error_at = p.len;
    emitCounter(&p, counters, 1);
    const exit_at = p.len;
    _ = p.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = p.emit(BPF.Insn.exit());
    p.patch(missing, error_at);
    p.patch(error_counter, error_at);
    p.patch(done, exit_at);
    return p;
}

fn observerProgram(counters: fd_t) Program {
    var p: Program = .{};
    _ = p.emit(BPF.Insn.ldx(.double_word, .r0, .r1, 0)); // ctx->sk
    const absent = p.emit(BPF.Insn.jeq(.r0, 0, 0));
    emitCounter(&p, counters, 2);
    const exit_at = p.len;
    _ = p.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = p.emit(BPF.Insn.exit());
    p.patch(absent, exit_at);
    return p;
}

fn dispatcherProgram(programs: fd_t) Program {
    var p: Program = .{};
    _ = p.emit(BPF.Insn.mov(.r2, programs)); // overwritten by ldimm64 below
    p.len = 0;
    _ = p.emit(BPF.Insn.ld_map_fd1(.r2, programs));
    _ = p.emit(BPF.Insn.ld_map_fd2(programs));
    _ = p.emit(BPF.Insn.mov(.r3, 0));
    _ = p.emit(BPF.Insn.call(.tail_call));
    _ = p.emit(BPF.Insn.mov(.r0, sk_pass));
    _ = p.emit(BPF.Insn.exit());
    return p;
}

fn emitCounter(p: *Program, counters: fd_t, key: u32) void {
    _ = p.emit(BPF.Insn.st(.word, .r10, -8, @intCast(key)));
    _ = p.emit(BPF.Insn.ld_map_fd1(.r1, counters));
    _ = p.emit(BPF.Insn.ld_map_fd2(counters));
    _ = p.emit(BPF.Insn.mov(.r2, .r10));
    _ = p.emit(BPF.Insn.add(.r2, -8));
    _ = p.emit(BPF.Insn.call(.map_lookup_elem));
    _ = p.emit(BPF.Insn.jeq(.r0, 0, 2));
    _ = p.emit(BPF.Insn.mov(.r1, 1));
    _ = p.emit(BPF.Insn.xadd(.r0, .r1));
}

fn totalInstructions(case: Case, selector: *const Program, observer: *const Program, dispatcher: *const Program) usize {
    return switch (case) {
        .direct, .cfg_load => selector.len,
        .chain => selector.len + observer.len,
        .tail_call => selector.len + dispatcher.len,
    };
}

fn emitResult(format: Format, case: Case, connect_ok: bool, accept_ok: bool, counters: fd_t, instructions: usize) !void {
    const assigned = try counter(counters, 0);
    const assign_errors = try counter(counters, 1);
    const ctx_seen = try counter(counters, 2);
    switch (format) {
        .json => std.debug.print("{{\"case\":\"{s}\",\"connect_result\":{},\"accept_result\":{},\"bpf_sk_assign_return_counter\":{d},\"bpf_sk_assign_error_counter\":{d},\"ctx_sk_seen\":{d},\"instruction_count\":{d}}}\n", .{ @tagName(case), connect_ok, accept_ok, assigned, assign_errors, ctx_seen, instructions }),
        .tsv => std.debug.print("{s}\t{}\t{}\t{d}\t{d}\t{d}\t{d}\n", .{ @tagName(case), connect_ok, accept_ok, assigned, assign_errors, ctx_seen, instructions }),
    }
}

fn socket() !fd_t {
    const rc = linux.socket(linux.AF.INET, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
    if (linux.errno(rc) != .SUCCESS) return error.SocketFailed;
    return @intCast(rc);
}

fn openListener(transparent: bool) !fd_t {
    const fd = try socket();
    errdefer closeFd(fd);
    const one: c_int = 1;
    if (linux.errno(linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.REUSEADDR, @ptrCast(&one), @sizeOf(c_int))) != .SUCCESS) return error.SetSockOptFailed;
    if (transparent and linux.errno(linux.setsockopt(fd, linux.SOL.IP, linux.IP.TRANSPARENT, @ptrCast(&one), @sizeOf(c_int))) != .SUCCESS) return error.SetTransparentFailed;
    var address = linux.sockaddr.in{ .port = std.mem.nativeToBig(u16, listen_port), .addr = 0 };
    if (linux.errno(linux.bind(fd, @ptrCast(&address), @sizeOf(@TypeOf(address)))) != .SUCCESS) return error.BindFailed;
    if (linux.errno(linux.listen(fd, 4)) != .SUCCESS) return error.ListenFailed;
    return fd;
}

fn acceptOne(fd: fd_t) !fd_t {
    const rc = linux.accept4(fd, null, null, linux.SOCK.CLOEXEC);
    if (linux.errno(rc) != .SUCCESS) return error.AcceptFailed;
    return @intCast(rc);
}

fn createMap(kind: BPF.MapType, key_size: u32, value_size: u32, max_entries: u32, name: []const u8) !fd_t {
    var attr: BPF.Attr = .{ .map_create = std.mem.zeroes(BPF.MapCreateAttr) };
    attr.map_create.map_type = @intFromEnum(kind);
    attr.map_create.key_size = key_size;
    attr.map_create.value_size = value_size;
    attr.map_create.max_entries = max_entries;
    @memcpy(attr.map_create.map_name[0..name.len], name);
    return bpfFd(.map_create, &attr, @sizeOf(BPF.MapCreateAttr), error.MapCreateFailed);
}

fn update(map: fd_t, key: []const u8, value: []const u8) !void {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map;
    attr.map_elem.key = @intFromPtr(key.ptr);
    attr.map_elem.result.value = @intFromPtr(value.ptr);
    if (linux.errno(linux.bpf(.map_update_elem, &attr, @sizeOf(BPF.MapElemAttr))) != .SUCCESS) return error.MapUpdateFailed;
}

fn counter(map: fd_t, key: u32) !u64 {
    var value: u64 = 0;
    var mutable_key = key;
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map;
    attr.map_elem.key = @intFromPtr(&mutable_key);
    attr.map_elem.result.value = @intFromPtr(&value);
    if (linux.errno(linux.bpf(.map_lookup_elem, &attr, @sizeOf(BPF.MapElemAttr))) != .SUCCESS) return error.MapLookupFailed;
    return value;
}

fn loadProgram(insns: []const BPF.Insn, name: []const u8) !fd_t {
    var log: [64 * 1024]u8 = @splat(0);
    const license = "GPL\x00";
    var attr: BPF.Attr = .{ .prog_load = std.mem.zeroes(BPF.ProgLoadAttr) };
    attr.prog_load.prog_type = @intFromEnum(BPF.ProgType.sk_lookup);
    attr.prog_load.expected_attach_type = @intFromEnum(BPF.AttachType.sk_lookup);
    attr.prog_load.insn_cnt = @intCast(insns.len);
    attr.prog_load.insns = @intFromPtr(insns.ptr);
    attr.prog_load.license = @intFromPtr(license.ptr);
    attr.prog_load.log_level = 1;
    attr.prog_load.log_size = log.len;
    attr.prog_load.log_buf = @intFromPtr(&log);
    @memcpy(attr.prog_load.prog_name[0..name.len], name);
    const rc = linux.bpf(.prog_load, &attr, @sizeOf(BPF.ProgLoadAttr));
    if (linux.errno(rc) != .SUCCESS) {
        const len = std.mem.indexOfScalar(u8, &log, 0) orelse log.len;
        std.debug.print("BPF verifier: {s}\n", .{log[0..len]});
        return error.ProgramLoadFailed;
    }
    return @intCast(rc);
}

fn openNetns() !fd_t {
    const path = "/proc/self/ns/net\x00";
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return error.OpenNetnsFailed;
    return @intCast(rc);
}

fn attach(program: fd_t, namespace: fd_t) !fd_t {
    var attr: BPF.Attr = .{ .link_create = std.mem.zeroes(BPF.LinkCreateAttr) };
    attr.link_create.prog_fd = program;
    attr.link_create.target_fd = namespace;
    attr.link_create.attach_type = @intFromEnum(BPF.AttachType.sk_lookup);
    const rc = linux.bpf(.link_create, &attr, @sizeOf(BPF.LinkCreateAttr));
    if (linux.errno(rc) != .SUCCESS) return error.ProgramAttachFailed;
    return @intCast(rc);
}

fn bpfFd(command: BPF.Cmd, attr: *BPF.Attr, size: u32, failure: anyerror) !fd_t {
    const rc = linux.bpf(command, attr, size);
    if (linux.errno(rc) != .SUCCESS) return failure;
    return @intCast(rc);
}

fn closeFd(fd: fd_t) void {
    _ = linux.close(fd);
}

test "matrix programs contain the intended helpers and scale CFG load" {
    const base = selectorProgram(10, 11, 0);
    const loaded = selectorProgram(10, 11, 37);
    const observer = observerProgram(11);
    const dispatcher = dispatcherProgram(12);
    try std.testing.expectEqual(base.len + 2 + 37 * 3, loaded.len);
    try std.testing.expectEqual(@as(usize, 1), helperCount(base.slice(), .sk_assign));
    try std.testing.expectEqual(@as(usize, 1), helperCount(dispatcher.slice(), .tail_call));
    try std.testing.expectEqual(@as(usize, 0), helperCount(observer.slice(), .sk_assign));
    try std.testing.expectEqual(BPF.Insn.ldx(.double_word, .r0, .r1, 0), observer.slice()[0]);
}

fn helperCount(insns: []const BPF.Insn, helper: BPF.Helper) usize {
    var count: usize = 0;
    for (insns) |insn| if (std.meta.eql(BPF.Insn.call(helper), insn)) {
        count += 1;
    };
    return count;
}
