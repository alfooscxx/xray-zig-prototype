const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const trace = b.option(bool, "trace", "Compile verbose protocol trace logging") orelse false;
    const build_options = b.addOptions();
    build_options.addOption(bool, "trace", trace);

    const mod = b.addModule("xray_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    mod.addOptions("build_options", build_options);

    const exe = b.addExecutable(.{
        .name = "xray-zig",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "xray_zig", .module = mod },
            },
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run xray-zig");
    run_step.dependOn(&run_cmd.step);

    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const exe_tests = b.addTest(.{ .root_module = exe.root_module });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    const quick_tests_cmd = b.addSystemCommand(&.{ "sh", "tests/xray-zig-quick.sh" });
    const quick_tests_step = b.step("test-quick", "Run xray-zig-quick lifecycle tests");
    quick_tests_step.dependOn(&quick_tests_cmd.step);
    test_step.dependOn(quick_tests_step);

    const e2e_reality_cmd = b.addSystemCommand(&.{ "bash", "tests/e2e/reality-xray.sh" });
    e2e_reality_cmd.addArtifactArg(exe);
    e2e_reality_cmd.has_side_effects = true;

    const e2e_reality_step = b.step("e2e-reality", "Run the opt-in Reality e2e harness against a real Xray server");
    e2e_reality_step.dependOn(&e2e_reality_cmd.step);

    const e2e_dns_cmd = b.addSystemCommand(&.{ "python3", "tests/e2e/dns-fallback.py" });
    e2e_dns_cmd.addArtifactArg(exe);
    e2e_dns_cmd.has_side_effects = true;

    const e2e_dns_step = b.step("e2e-dns", "Run concurrent outbound-routed DNS-over-TCP tests");
    e2e_dns_step.dependOn(&e2e_dns_cmd.step);

    const e2e_fakedns_freedom_cmd = b.addSystemCommand(&.{ "python3", "tests/e2e/fakedns-freedom.py" });
    e2e_fakedns_freedom_cmd.addArtifactArg(exe);
    e2e_fakedns_freedom_cmd.has_side_effects = true;

    const e2e_fakedns_freedom_step = b.step("e2e-fakedns-freedom", "Run FakeDNS freedom resolution regression");
    e2e_fakedns_freedom_step.dependOn(&e2e_fakedns_freedom_cmd.step);

    const ebpf_lab_peer = b.addExecutable(.{
        .name = "ebpf-lab-peer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/field/ebpf-lab-peer.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "xray_zig", .module = mod }},
        }),
    });
    const install_ebpf_lab_peer = b.addInstallArtifact(ebpf_lab_peer, .{});
    const ebpf_lab_peer_step = b.step("ebpf-lab-peer", "Build the isolated SK_LOOKUP lab peer");
    ebpf_lab_peer_step.dependOn(&install_ebpf_lab_peer.step);

    const ebpf_sockhash_selftest = b.addExecutable(.{
        .name = "ebpf-sockhash-selftest",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/field/ebpf-sockhash-selftest.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "xray_zig", .module = mod }},
        }),
    });
    const install_ebpf_sockhash_selftest = b.addInstallArtifact(ebpf_sockhash_selftest, .{});
    const ebpf_sockhash_selftest_step = b.step("ebpf-sockhash-selftest", "Build the privileged TCP SOCKHASH capability selftest");
    ebpf_sockhash_selftest_step.dependOn(&install_ebpf_sockhash_selftest.step);
}
