//! Get and set ACLs (aclapi.h)
// https://stackoverflow.com/questions/14849221/how-to-get-acl-permissions-for-a-folder-for-a-specific-user-with-c
// https://github.com/MagnusTiberius/win32acl
// https://github.com/MagnusTiberius/win32acl/blob/master/win32acl.cpp
// https://learn.microsoft.com/en-us/windows/win32/secauthz/modifying-the-acls-of-an-object-in-c--
// https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
// https://learn.microsoft.com/en-us/archive/msdn-magazine/2008/november/access-control-understanding-windows-file-and-registry-permissions
// https://learn.microsoft.com/de-de/windows/win32/api/ntsecapi/nf-ntsecapi-lsaopenpolicy?redirectedfrom=MSDN
// https://learn.microsoft.com/de-de/windows/win32/secauthz/searching-for-a-sid-in-an-access-token-in-c--
// https://stackoverflow.com/questions/3670984/gettokeninformation-first-call-what-for
// https://stackoverflow.com/questions/73303801/check-if-a-different-process-is-running-with-elevated-privileges
// https://learn.microsoft.com/en-us/windows/win32/secauthz/finding-the-owner-of-a-file-object-in-c--

// https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers
// https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
// https://woshub.com/convert-sid-to-username-and-vice-versa/
// https://stackoverflow.com/questions/65988701/use-of-lookupaccountsidw
// https://cpp.hotexamples.com/examples/-/-/LookupAccountSid/cpp-lookupaccountsid-function-examples.html

// ci: run the same frmo elevated permissions, admin user and non-admin user
//     and provide context as cli flag
// https://superuser.com/questions/55809/how-to-run-program-from-command-line-with-elevated-rights

const std = @import("std");
const sec = @import("sec");
const winsec = sec.os.win;
const childsec = sec.child;
const ossec = sec.os;

pub extern fn GetLastError() winsec.DWORD;

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer if (gpa_state.deinit() != .ok) {
        @panic("found memory leaks");
    };
    const gpa = gpa_state.allocator();
    try behavior(gpa);
}

fn isProcessElevated() !bool {
    const TA = winsec.TOKEN_ACCESS;
    const h_token = try winsec.OpenProcessToken(winsec.GetCurrentProcess(), @intFromEnum(TA.QUERY));
    defer std.os.close(h_token);
    var elevation: winsec.TOKEN_ELEVATION = undefined;
    const expected_size = @sizeOf(winsec.TOKEN_ELEVATION);

    const TI = winsec.TokenInfo;
    const size = try winsec.GetTokenInformation(h_token, TI.Elevation, &elevation, expected_size);
    try std.testing.expectEqual(size, expected_size);
    return elevation.TokenIsElevated != 0;
}

const CallContext = enum {
    Privileged,
    Standard,
    Reduced,
};

fn behavior(gpa: std.mem.Allocator) !void {
    const L = std.unicode.utf8ToUtf16LeStringLiteral;
    var it = try std.process.argsWithAllocator(gpa);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name

    const tmpDir = std.testing.tmpDir;
    var tmp = tmpDir(.{});
    defer tmp.cleanup();
    var file_user_h: ?std.fs.File.Handle = null;
    const file_user = try tmp.dir.createFile("file_user", .{ .read = true });
    defer file_user.close();
    file_user_h = file_user.handle;

    const sec_info = try winsec.GetSecurityInfo(
        file_user_h,
        winsec.SE_OBJECT_TYPE.FILE_OBJECT,
        @intFromEnum(winsec.SECURITY_INFORMATION.OWNER),
    );

    std.debug.print("sec_info: {}\n", .{ sec_info });
    std.debug.print("sec_info.sid_owner: {any}\n", .{ sec_info.sid_owner });
    std.debug.print("sec_info.sid_owner: {any}\n", .{ sec_info.sid_owner.? });
    std.debug.print("sec_info.sid_owner: {any}\n", .{ sec_info.sid_owner.?.* });
    std.debug.print("sec_info.sid_owner: {any}\n", .{ sec_info.sid_owner.?.*.? });

    var acc_name: winsec.LPWSTR = @as([*:0]u16, @constCast(L("")));
    var size_acc_name: winsec.DWORD = 0;
    var domain_name: winsec.LPWSTR = @as([*:0]u16, @constCast(L("")));
    var size_domain_name: winsec.DWORD = 0;
    var eUse: winsec.SID_NAME_USE = winsec.SID_NAME_USE.Unknown;

// pub extern fn LookupAccountSidW(
//      lpSystemName: LPCWSTR,
//      Sid: PSID,
//      Name: LPWSTR,
//      cchName: LPDWORD,
//      ReferencedDomainName: LPWSTR,
//      cchReferencedDomainName: LPDWORD,
//      peUse: PSID_NAME_USE
//  ) WINBOOL;
// bRtnBool = LookupAccountSidW(
//      null,
//      pSidOwner,
//      AcctName,
//      @as(LPDWORD, @ptrCast(@alignCast(&dwAcctName))),
//      DomainName,
//      @as(LPDWORD, @ptrCast(@alignCast(&dwDomainName))),
//      &eUse
//  );
    // const sid_owner = sec_info.sid_owner.?.*;

    // wrong parameters segfault with bogous error 3 (PATH_NOT_FOUND)
    // const st = winsec.advapi32.LookupAccountSidW(
    //     null,
    //     null, // sid_owner,
    //     null,
    //     &size_acc_name,
    //     null,
    //     &size_domain_name,
    //     &eUse,
    // );
    // if (st == 0) {
    //     const err = winsec.kernel32.GetLastError();
    //     std.debug.print("error code: {d}\n", .{ err });
    //     return error.InvalValue;
    // }

    // fails via INVAL_PARAMETER, if second param == null and
    // SEGFAULT otherwise with error 3 (PATH_NOT_FOUND)
    try winsec.LookupAccountSid(
        null,
        sec_info.sid_owner.?.*, // sid_owner,
        acc_name[0..],
        &size_acc_name,
        domain_name[0..],
        &size_domain_name,
        &eUse,
    );

    // try winsec.LookupAccountSid(
    //     null,
    //     sec_info.sid_owner.?.*,
    //     acc_name[0..],
    //     &size_acc_name,
    //     domain_name[0..],
    //     &size_domain_name,
    //     &eUse,
    // );

    // TODO
    // var account_buf: [100]

    // TODO
    // https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-operations

    // GetExplicitEntriesFromAcl
    // Major footgun on setting security permissions.
    // https://stackoverflow.com/questions/35227184/what-is-the-counterpart-to-the-getexplicitentriesfromacl-win32-api-function
    // yes, its that simple.
    // https://learn.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-geteffectiverightsfromacla

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