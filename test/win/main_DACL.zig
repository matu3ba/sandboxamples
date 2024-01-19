//! Get and set ACLs.
// https://stackoverflow.com/questions/14849221/how-to-get-acl-permissions-for-a-folder-for-a-specific-user-with-c
// https://github.com/MagnusTiberius/win32acl
// https://github.com/MagnusTiberius/win32acl/blob/master/win32acl.cpp
// https://learn.microsoft.com/en-us/windows/win32/secauthz/modifying-the-acls-of-an-object-in-c--
// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
// https://learn.microsoft.com/en-us/archive/msdn-magazine/2008/november/access-control-understanding-windows-file-and-registry-permissions
// https://learn.microsoft.com/de-de/windows/win32/api/ntsecapi/nf-ntsecapi-lsaopenpolicy?redirectedfrom=MSDN

// ci: run the same frmo elevated permissions, admin user and non-admin user
//     and provide context as cli flag
// https://superuser.com/questions/55809/how-to-run-program-from-command-line-with-elevated-rights

const std = @import("std");
const sec = @import("sec");
const winsec = sec.os.win;
const childsec = sec.child;
const ossec = sec.os;

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer if (gpa_state.deinit() != .ok) {
        @panic("found memory leaks");
    };
    const gpa = gpa_state.allocator();
    try behavior(gpa);
}

fn isProcessElevated() !bool {
    var h_token: winsec.HANDLE = undefined;
    try winsec.OpenProcessToken(winsec.GetCurrentProcess(), winsec.TOKEN.QUERY, &h_token);
    defer std.os.close(h_token);
    var elevation: winsec.TOKEN_ELEVATION = undefined;
    var cb_size = @sizeOf(winsec.TOKEN_ELEVATION);

    try winsec.GetTokenInformation(h_token, winsec.TokenElevation, &elevation, winsec.TOKEN_ELEVATION, &cb_size);
    return elevation.TokenIsElevated != 0;
}

const CallContext = enum {
    Privileged,
    Standard,
    Reduced,
};

fn behavior(gpa: std.mem.Allocator) !void {
    const L = std.unicode.utf8ToUtf16LeStringLiteral;
    _ = L;
    var it = try std.process.argsWithAllocator(gpa);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name
    // Caller_context may be 1. privileged, 2. user 1, user 2 with
    // privilege level admin. Leave ut system for now.
    const caller_context_cli = it.next() orelse @panic("missing caller context to test expected behavior");
    const child_path = it.next() orelse @panic("missing child path");
    _ = child_path;

    // Permissions can only be given on spawning process, not afterwards.
    const is_process_elevated = try isProcessElevated();
    // const call_context = ctx: {
    //     if (std.mem.eql(u8, caller_context_cli, "privileged")) break :ctx .Privileged;
    //     else if (std.mem.eql(u8, caller_context_cli, "suser1")) break :ctx .Standard;
    //     else if (std.mem.eql(u8, caller_context_cli, "ruser1")) break :ctx .Reduced;
    // TODO how check callcontext against standard or reduced privileges

    const call_context: CallContext = if (std.mem.eql(u8, caller_context_cli, "privileged"))
        CallContext.Privileged
    else
        CallContext.Standard;

    switch (call_context) {
        .Privileged => try std.testing.expectEqual(is_process_elevated, true),
        .Standard => try std.testing.expectEqual(is_process_elevated, false),
        .Reduced => @panic("unreachable"),
    }

    // - 1. check current capabilities to impersonate a user or adjust a file owned by another user
    // - 2. create some files of 2.1 different user, 2.2 same user, 2.3 admin
    //   - ask for permissions
    //   - run the same frmo elevated permissions
    // - 3. drop privileges in the child process and try adding files or
    // deleting files of that disallowed path and an allowed one



    // create job object and set information
    // const h_jo = winsec.CreateJobObject(null, null);
    // defer std.os.close(h_jo);
    // var jo_eli = std.mem.zeroes(winsec.JOBOBJECT_EXTENDED_LIMIT_INFORMATION);
    // jo_eli.BasicLimitInformation.LimitFlags =
    //     @intFromEnum(winsec.JOB_OBJECT_LIMIT.KILL_ON_JOB_CLOSE)
    //     | @intFromEnum(winsec.JOB_OBJECT_LIMIT.JOB_MEMORY)
    //     | @intFromEnum(winsec.JOB_OBJECT_LIMIT.ACTIVE_PROCESS)
    //     | @intFromEnum(winsec.JOB_OBJECT_LIMIT.JOB_TIME);
    // jo_eli.JobMemoryLimit = 20_971_520; // [B] => 20 MB = 20 * (1024)^2 B = 20 * 1_048_576 = 20_971_520 B
    // jo_eli.BasicLimitInformation.ActiveProcessLimit = 32;
    // jo_eli.BasicLimitInformation.PerJobUserTimeLimit = 1_000 * 1_000 * 10; // 1s = 1_000 * 1_000 * 10 * 100ns
    // try winsec.SetInformationJobObject(h_jo, winsec.JobObjectInformationClass.ExtendedLimitInformation, &jo_eli, @sizeOf(@TypeOf(jo_eli)));
    //
    // var attrs: winsec.LPPROC_THREAD_ATTRIBUTE_LIST = undefined;
    // var attrs_len: winsec.SIZE_T = undefined;
    //
    // // Intentional probing. Alternative is to use ntdll directly.
    // try std.testing.expectError(error.InsufficientBuffer, winsec.InitializeProcThreadAttributeList(null, 1, 0, &attrs_len));
    // var attrs_buf: []u8 = undefined;
    // attrs_buf = try gpa.alloc(u8, attrs_len);
    // defer gpa.free(attrs_buf);
    // @memset(attrs_buf, 0);
    // attrs = @alignCast(@ptrCast(attrs_buf));
    // try winsec.InitializeProcThreadAttributeList(attrs, 1, 0, &attrs_len);
    //
    // try winsec.UpdateProcThreadAttribute(
    //     attrs,
    //     0,
    //     // ProcThreadAttributeJobList
    //     winsec.PROC_THREAD_ATTRIBUTE_JOB_LIST,
    //     @as(*anyopaque, @ptrCast(@constCast(&h_jo))),
    //     @sizeOf(@TypeOf(h_jo)),
    //     null,
    //     null,
    // );
    //
    // var child = childsec.ChildProcess.init(&.{ child_path, "6" }, gpa);
    // child.stdin_behavior = .Close;
    // child.stdout_behavior = .Inherit;
    // child.stderr_behavior = .Inherit;
    // child.proc_thread_attr_list = attrs;
    // // CANCELLED = 1223 should be in u32, but we get then error code 199 by windows
    // // @intFromEnum(winsec.Win32Error.CANCELLED);
    // const expected_exit_code: u32 = 1;
    //                                       //
    // std.debug.assert(expected_exit_code > 0);
    //
    // { // alive subprocesses block
    //     try child.spawn();
    //     const isproc_injob = try winsec.IsProcessInJob(child.id, h_jo);
    //     try std.testing.expectEqual(isproc_injob, true);
    //     // kill descendant processes in all cases
    //     defer winsec.TerminateJobObject(h_jo, expected_exit_code) catch {}; // does this error code make sense?
    //
    //     // some work, supervision, forward debugging etc
    // }
    //
    // // no surviving processes must exist (bindings exhaustive work, so defer it)
    // const has_prefix = hasAnyProcessPrefix(L("evildescendent"));
    // if (has_prefix) return error.ProcessHasUnwantedPrefix;
    //
    // const wait_res = try child.wait();
    // switch (wait_res) {
    //     .Exited => |code| {
    //         if (code != expected_exit_code) {
    //             std.debug.print("child exit code: {d}\n", .{code});
    //             return error.NonZeroExitCode;
    //         }
    //     },
    //     else => |term| {
    //         std.debug.print("abnormal child exit: {}\n", .{term});
    //         return error.AbnormalChildExit;
    //     }
    // }
}