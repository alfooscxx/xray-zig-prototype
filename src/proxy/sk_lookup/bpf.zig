const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;

const fakedns = @import("../../dns/fakedns.zig");
const log = @import("../../log.zig");

const linux = std.os.linux;
const BPF = linux.BPF;
const fd_t = std.posix.fd_t;

const af_inet = 2;
const af_inet6 = 10;
const ipproto_tcp = 6;
const sk_pass = 1;
const listener4_key: u32 = 0;
const listener6_key: u32 = 1;

// Stable UAPI layout of struct bpf_sk_lookup. No kernel BTF is required.
const SkLookupContext = extern struct {
    selected_socket: u64,
    family: u32,
    protocol: u32,
    remote_ip4: u32,
    remote_ip6: [4]u32,
    remote_port_and_padding: u32,
    local_ip4: u32,
    local_ip6: [4]u32,
    local_port: u32,
    ingress_ifindex: u32,
};

comptime {
    std.debug.assert(@offsetOf(SkLookupContext, "protocol") == 12);
    std.debug.assert(@offsetOf(SkLookupContext, "local_ip4") == 40);
    std.debug.assert(@offsetOf(SkLookupContext, "local_ip6") == 44);
}

pub const Dataplane = struct {
    fake4_fd: fd_t,
    fake6_fd: fd_t,
    listeners_fd: fd_t,
    program_fd: fd_t,
    link_fd: fd_t,

    pub fn init(max_entries: u32, listener4_fd: fd_t, listener6_fd: fd_t, io: Io) !Dataplane {
        if (builtin.os.tag != .linux) return error.SkLookupRequiresLinux;

        const fake4_fd = try createMap(.hash, 4, @sizeOf(fakedns.Publication), max_entries, "xz_fake4");
        errdefer closeFd(fake4_fd);
        const fake6_fd = try createMap(.hash, 16, @sizeOf(fakedns.Publication), max_entries, "xz_fake6");
        errdefer closeFd(fake6_fd);
        const listeners_fd = try createMap(.sockmap, @sizeOf(u32), @sizeOf(u32), 2, "xz_listeners");
        errdefer closeFd(listeners_fd);

        try update(listeners_fd, std.mem.asBytes(&listener4_key), std.mem.asBytes(&listener4_fd));
        try update(listeners_fd, std.mem.asBytes(&listener6_key), std.mem.asBytes(&listener6_fd));

        const instructions = program(fake4_fd, fake6_fd, listeners_fd);
        const program_fd = try loadProgram(&instructions);
        errdefer closeFd(program_fd);

        var namespace = try Io.Dir.openFileAbsolute(io, "/proc/self/ns/net", .{});
        defer namespace.close(io);
        const link_fd = try createLink(program_fd, namespace.handle);

        return .{
            .fake4_fd = fake4_fd,
            .fake6_fd = fake6_fd,
            .listeners_fd = listeners_fd,
            .program_fd = program_fd,
            .link_fd = link_fd,
        };
    }

    pub fn deinit(self: *Dataplane) void {
        closeFd(self.link_fd);
        closeFd(self.program_fd);
        closeFd(self.listeners_fd);
        closeFd(self.fake6_fd);
        closeFd(self.fake4_fd);
        self.* = undefined;
    }

    pub fn publisher(self: *Dataplane) fakedns.Publisher {
        return .{
            .context = self,
            .publish4_fn = publish4,
            .publish6_fn = publish6,
            .remove4_fn = remove4,
            .remove6_fn = remove6,
        };
    }

    fn publish4(context: ?*anyopaque, address: [4]u8, value: fakedns.Publication) !void {
        const self: *Dataplane = @ptrCast(@alignCast(context.?));
        try update(self.fake4_fd, &address, std.mem.asBytes(&value));
    }

    fn publish6(context: ?*anyopaque, address: [16]u8, value: fakedns.Publication) !void {
        const self: *Dataplane = @ptrCast(@alignCast(context.?));
        try update(self.fake6_fd, &address, std.mem.asBytes(&value));
    }

    fn remove4(context: ?*anyopaque, address: [4]u8) void {
        const self: *Dataplane = @ptrCast(@alignCast(context.?));
        delete(self.fake4_fd, &address);
    }

    fn remove6(context: ?*anyopaque, address: [16]u8) void {
        const self: *Dataplane = @ptrCast(@alignCast(context.?));
        delete(self.fake6_fd, &address);
    }
};

fn createMap(map_type: BPF.MapType, key_size: u32, value_size: u32, max_entries: u32, name: []const u8) !fd_t {
    var attr: BPF.Attr = .{ .map_create = std.mem.zeroes(BPF.MapCreateAttr) };
    attr.map_create.map_type = @intFromEnum(map_type);
    attr.map_create.key_size = key_size;
    attr.map_create.value_size = value_size;
    attr.map_create.max_entries = max_entries;
    @memcpy(attr.map_create.map_name[0..name.len], name);
    const rc = linux.bpf(.map_create, &attr, @sizeOf(BPF.MapCreateAttr));
    return fdResult(rc, error.BpfMapCreateFailed);
}

fn update(map_fd: fd_t, key: []const u8, value: []const u8) !void {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key.ptr);
    attr.map_elem.result.value = @intFromPtr(value.ptr);
    const rc = linux.bpf(.map_update_elem, &attr, @sizeOf(BPF.MapElemAttr));
    if (linux.errno(rc) != .SUCCESS) return error.BpfMapUpdateFailed;
}

fn delete(map_fd: fd_t, key: []const u8) void {
    var attr: BPF.Attr = .{ .map_elem = std.mem.zeroes(BPF.MapElemAttr) };
    attr.map_elem.map_fd = map_fd;
    attr.map_elem.key = @intFromPtr(key.ptr);
    const rc = linux.bpf(.map_delete_elem, &attr, @sizeOf(BPF.MapElemAttr));
    switch (linux.errno(rc)) {
        .SUCCESS, .NOENT => {},
        else => {},
    }
}

fn loadProgram(instructions: []const BPF.Insn) !fd_t {
    var verifier_log: [64 * 1024]u8 = @splat(0);
    const license = "GPL\x00";
    var attr: BPF.Attr = .{ .prog_load = std.mem.zeroes(BPF.ProgLoadAttr) };
    attr.prog_load.prog_type = @intFromEnum(BPF.ProgType.sk_lookup);
    attr.prog_load.insn_cnt = @intCast(instructions.len);
    attr.prog_load.insns = @intFromPtr(instructions.ptr);
    attr.prog_load.license = @intFromPtr(license.ptr);
    attr.prog_load.log_level = 1;
    attr.prog_load.log_size = verifier_log.len;
    attr.prog_load.log_buf = @intFromPtr(&verifier_log);
    attr.prog_load.expected_attach_type = @intFromEnum(BPF.AttachType.sk_lookup);
    const name = "xz_sk_lookup";
    @memcpy(attr.prog_load.prog_name[0..name.len], name);
    const rc = linux.bpf(.prog_load, &attr, @sizeOf(BPF.ProgLoadAttr));
    if (linux.errno(rc) != .SUCCESS) {
        verifier_log[verifier_log.len - 1] = 0;
        const length = std.mem.indexOfScalar(u8, &verifier_log, 0) orelse verifier_log.len;
        log.warn("SK_LOOKUP BPF verifier rejected program: {s}\n", .{verifier_log[0..length]});
        return error.BpfProgramLoadFailed;
    }
    return @intCast(rc);
}

fn createLink(program_fd: fd_t, namespace_fd: fd_t) !fd_t {
    var attr: BPF.Attr = .{ .link_create = std.mem.zeroes(BPF.LinkCreateAttr) };
    attr.link_create.prog_fd = program_fd;
    attr.link_create.target_fd = namespace_fd;
    attr.link_create.attach_type = @intFromEnum(BPF.AttachType.sk_lookup);
    const rc = linux.bpf(.link_create, &attr, @sizeOf(BPF.LinkCreateAttr));
    return fdResult(rc, error.BpfLinkCreateFailed);
}

fn fdResult(rc: usize, failure: anyerror) !fd_t {
    if (linux.errno(rc) != .SUCCESS) return failure;
    return @intCast(rc);
}

fn closeFd(fd: fd_t) void {
    _ = linux.close(fd);
}

fn program(fake4_fd: fd_t, fake6_fd: fd_t, listeners_fd: fd_t) [68]BPF.Insn {
    return .{
        BPF.Insn.mov(.r6, .r1),
        BPF.Insn.mov(.r0, sk_pass),
        BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "protocol")),
        BPF.Insn.jne(.r2, ipproto_tcp, 62),
        BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "family")),
        BPF.Insn.jeq(.r2, af_inet, 34),
        BPF.Insn.jne(.r2, af_inet6, 59),

        BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip6")),
        BPF.Insn.stx(.word, .r10, -16, .r2),
        BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip6") + 4),
        BPF.Insn.stx(.word, .r10, -12, .r2),
        BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip6") + 8),
        BPF.Insn.stx(.word, .r10, -8, .r2),
        BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip6") + 12),
        BPF.Insn.stx(.word, .r10, -4, .r2),
        BPF.Insn.ld_map_fd1(.r1, fake6_fd),
        BPF.Insn.ld_map_fd2(fake6_fd),
        BPF.Insn.mov(.r2, .r10),
        BPF.Insn.add(.r2, -16),
        BPF.Insn.call(.map_lookup_elem),
        BPF.Insn.jeq(.r0, 0, 45),
        BPF.Insn.mov(.r7, .r0),
        BPF.Insn.call(.ktime_get_ns),
        BPF.Insn.ldx(.double_word, .r8, .r7, 16),
        BPF.Insn.jge(.r0, .r8, 41),
        BPF.Insn.st(.word, .r10, -20, listener6_key),
        BPF.Insn.ld_map_fd1(.r1, listeners_fd),
        BPF.Insn.ld_map_fd2(listeners_fd),
        BPF.Insn.mov(.r2, .r10),
        BPF.Insn.add(.r2, -20),
        BPF.Insn.call(.map_lookup_elem),
        BPF.Insn.jeq(.r0, 0, 34),
        BPF.Insn.mov(.r7, .r0),
        BPF.Insn.mov(.r1, .r6),
        BPF.Insn.mov(.r2, .r7),
        BPF.Insn.mov(.r3, 0),
        BPF.Insn.call(.sk_assign),
        BPF.Insn.mov(.r1, .r7),
        BPF.Insn.call(.sk_release),
        BPF.Insn.ja(26),

        BPF.Insn.ldx(.word, .r2, .r6, @offsetOf(SkLookupContext, "local_ip4")),
        BPF.Insn.stx(.word, .r10, -4, .r2),
        BPF.Insn.ld_map_fd1(.r1, fake4_fd),
        BPF.Insn.ld_map_fd2(fake4_fd),
        BPF.Insn.mov(.r2, .r10),
        BPF.Insn.add(.r2, -4),
        BPF.Insn.call(.map_lookup_elem),
        BPF.Insn.jeq(.r0, 0, 18),
        BPF.Insn.mov(.r7, .r0),
        BPF.Insn.call(.ktime_get_ns),
        BPF.Insn.ldx(.double_word, .r8, .r7, 16),
        BPF.Insn.jge(.r0, .r8, 14),
        BPF.Insn.st(.word, .r10, -20, listener4_key),
        BPF.Insn.ld_map_fd1(.r1, listeners_fd),
        BPF.Insn.ld_map_fd2(listeners_fd),
        BPF.Insn.mov(.r2, .r10),
        BPF.Insn.add(.r2, -20),
        BPF.Insn.call(.map_lookup_elem),
        BPF.Insn.jeq(.r0, 0, 7),
        BPF.Insn.mov(.r7, .r0),
        BPF.Insn.mov(.r1, .r6),
        BPF.Insn.mov(.r2, .r7),
        BPF.Insn.mov(.r3, 0),
        BPF.Insn.call(.sk_assign),
        BPF.Insn.mov(.r1, .r7),
        BPF.Insn.call(.sk_release),

        BPF.Insn.mov(.r0, sk_pass),
        BPF.Insn.exit(),
    };
}

test "SK_LOOKUP program has stable UAPI-only instruction layout" {
    const instructions = program(10, 11, 12);
    try std.testing.expectEqual(@as(usize, 68), instructions.len);
    try std.testing.expectEqual(BPF.Insn.call(.sk_assign), instructions[36]);
    try std.testing.expectEqual(BPF.Insn.call(.sk_release), instructions[38]);
    try std.testing.expectEqual(BPF.Insn.call(.sk_assign), instructions[63]);
    try std.testing.expectEqual(BPF.Insn.call(.sk_release), instructions[65]);
    try std.testing.expectEqual(BPF.Insn.exit(), instructions[instructions.len - 1]);
}
