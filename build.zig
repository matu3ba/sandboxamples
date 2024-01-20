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
            const step_ehinh = b.step("runehinh", "Run win explicit handle inheritance test.");
            step_ehinh.dependOn(&r_step_ehinherit.step);
            test_step.dependOn(&r_step_ehinherit.step);
        }
    }

    {
        const child = b.addExecutable(.{
            .name = "child_win32k_mitigation",
            .root_source_file = .{ .path = "test/win/child_win32k_mitigation.zig" },
            .optimize = optimize,
            .target = target,
        });
        child.root_module.addImport("sec", sec);
        b.installArtifact(child);

        const main = b.addExecutable(.{
            .name = "main_win32k_mitigation",
            .root_source_file = .{ .path = "test/win/main_win32k_mitigation.zig" },
            .optimize = optimize,
            .target = target,
        });
        main.root_module.addImport("sec", sec);
        b.installArtifact(main);

        const r_step_win32kmit = b.addRunArtifact(main);
        r_step_win32kmit.addArtifactArg(child);
        r_step_win32kmit.step.dependOn(b.getInstallStep());
        r_step_win32kmit.expectExitCode(0);

        if (b.host.result.os.tag == .windows) {
            const step_miti = b.step("runwin32kmit", "Run win32k mitigation test.");
            step_miti.dependOn(&r_step_win32kmit.step);
            test_step.dependOn(&r_step_win32kmit.step);
        }
    }

    {
        const child = b.addExecutable(.{
            .name = "evildescendent_child_job_api",
            .root_source_file = .{ .path = "test/win/child_job_api.zig" },
            .optimize = optimize,
            .target = target,
        });
        child.root_module.addImport("sec", sec);
        b.installArtifact(child);

        const main = b.addExecutable(.{
            .name = "main_job_api",
            .root_source_file = .{ .path = "test/win/main_job_api.zig" },
            .optimize = optimize,
            .target = target,
        });
        main.root_module.addImport("sec", sec);
        b.installArtifact(main);

        const r_step_jobapi = b.addRunArtifact(main);
        r_step_jobapi.addArtifactArg(child);
        r_step_jobapi.step.dependOn(b.getInstallStep());
        r_step_jobapi.expectExitCode(0);

        if (b.host.result.os.tag == .windows) {
            const step_miti = b.step("runwinjobapi", "Run win job api test.");
            step_miti.dependOn(&r_step_jobapi.step);
            test_step.dependOn(&r_step_jobapi.step);
        }
    }

    {
        // const child = b.addExecutable(.{
        //     .name = "child_acl",
        //     .root_source_file = .{ .path = "test/win/child_DCAL.zig" },
        //     .optimize = optimize,
        //     .target = target,
        // });
        // child.root_module.addImport("sec", sec);
        // b.installArtifact(child);

        const main = b.addExecutable(.{
            .name = "main_acl",
            .root_source_file = .{ .path = "test/win/main_ACL.zig" },
            .optimize = optimize,
            .target = target,
        });
        main.root_module.addImport("sec", sec);
        b.installArtifact(main);

        const r_step_win_acl = b.addRunArtifact(main);
        r_step_win_acl.addArg("standard");
        // r_step_win_acl.addArtifactArg(child);
        r_step_win_acl.step.dependOn(b.getInstallStep());
        r_step_win_acl.expectExitCode(0);

        if (b.host.result.os.tag == .windows) {
            const step_miti = b.step("runwinacl", "Run win acl test.");
            step_miti.dependOn(&r_step_win_acl.step);
            test_step.dependOn(&r_step_win_acl.step);
        }
    }
}