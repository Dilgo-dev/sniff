const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const glym_dep = b.dependency("glym", .{ .target = target, .optimize = optimize });

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("glym", glym_dep.module("glym"));

    // Windows uses raw sockets via ws2_32 (no extra install)
    if (target.result.os.tag == .windows) {
        exe_mod.linkSystemLibrary("ws2_32", .{});
    }

    const exe = b.addExecutable(.{
        .name = "sniff",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    const run_step = b.step("run", "Run the packet sniffer");
    run_step.dependOn(&run.step);

    const test_step = b.step("test", "Run unit tests");

    const pkt_test_mod = b.createModule(.{
        .root_source_file = b.path("src/packet.zig"),
        .target = target,
        .optimize = optimize,
    });
    const pkt_tests = b.addTest(.{ .root_module = pkt_test_mod });
    test_step.dependOn(&b.addRunArtifact(pkt_tests).step);

    const filter_test_mod = b.createModule(.{
        .root_source_file = b.path("src/filter.zig"),
        .target = target,
        .optimize = optimize,
    });
    const filter_tests = b.addTest(.{ .root_module = filter_test_mod });
    test_step.dependOn(&b.addRunArtifact(filter_tests).step);
}
