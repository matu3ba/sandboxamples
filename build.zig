const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const mem = std.mem;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sec = b.createModule(.{ .root_source_file = .{ .path = "sec.zig" } });

    if (builtin.os.tag == .wasi) return;
    const test_step = b.step("test", "Run unit tests");

    {
        const child = b.addExecutable(.{
            .name = "child_explicit_handle_inheritance",
            .root_source_file = .{ .path = "test/win/child_explicit_handle_inheritance.zig" },
            .optimize = optimize,
            .target = target,
        });
        child.root_module.addImport("sec", sec);
        b.installArtifact(child);

        const main = b.addExecutable(.{
            .name = "main_explicit_handle_inheritance",
            .root_source_file = .{ .path = "test/win/main_explicit_handle_inheritance.zig" },
            .optimize = optimize,
            .target = target,
        });
        main.root_module.addImport("sec", sec);
        b.installArtifact(main);

        const r_step_ehinherit = b.addRunArtifact(main);
        r_step_ehinherit.addArtifactArg(child);
        r_step_ehinherit.step.dependOn(b.getInstallStep());
        r_step_ehinherit.expectExitCode(0);

        if (b.host.result.os.tag == .windows) {
            const step_zmiti = b.step("runehinh", "Run explicit handle inheritance test.");
            step_zmiti.dependOn(&r_step_ehinherit.step);
            test_step.dependOn(&r_step_ehinherit.step);
        }
    }
}