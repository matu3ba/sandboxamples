//! Test killing child kills all 6 descendants based on
//! * https://devblogs.microsoft.com/oldnewthing/20131209-00/?p=2433
//! * https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812
//! * https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject
//! * https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_limit_information
//! * https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-freememoryjobobject
//! This includes setting common process limits.
//! - 0. basic test
//! - 1. higher process spawn api to remain alive
//! - 2. CreateProcess flags to break away from parent process to remain alive
//!      * good way to test, if win32k mitigation works
//! - 3. "fork bomb" the system
//! - 4. use maximum memory
//! - 5. exhaust kernel memory via pipe buffer usage
//! - 6. request admin privileges from user
//! Descendent processes intended to be named "evildescendent" for checks.
//!
//! Validate running still running processes with
//! * https://learn.microsoft.com/de-de/windows/win32/psapi/enumerating-all-processes?redirectedfrom=MSDN

// TODO
// - replace use cases of FreeMemoryJobObject
// - checkNoProcessHasPrefix
// - atomic guarantees of Windows regarding system process overview?
// - trace process spawn via etw?

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

// This check may be racy, because Windows does not document that accesses to
// process information is automic.
// fn checkNoProcessHasPrefix(pid: u32) !void {
//     var path_buf: [std.win.fs.MAX_PATH]u8 = undefined;
//     var h_proc: *anyopaque = winsec.OpenProcess(
//         winsec.PROCESS_QUERY_INFORMATION | winsec.PROCESS_VM_READ,
//         false,
//         pid,
//     );
//     var h_mod: winsec.H
//     if (null != h_proc) {
//         EnumProcessModules(h_proc, &hmod
//
//     }
// }

fn behavior(gpa: std.mem.Allocator) !void {
    var it = try std.process.argsWithAllocator(gpa);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name
    const child_path = it.next() orelse @panic("missing child path");

    const jo = winsec.CreateJobObject(null, null);
    defer std.os.close(jo);
    var attrs: winsec.LPPROC_THREAD_ATTRIBUTE_LIST = undefined;
    var attrs_len: winsec.SIZE_T = undefined;

    // Intentional probing. Alternative is to use ntdll directly.
    try std.testing.expectError(error.InsufficientBuffer, winsec.InitializeProcThreadAttributeList(null, 1, 0, &attrs_len));
    var attrs_buf: []u8 = undefined;
    attrs_buf = try gpa.alloc(u8, attrs_len);
    defer gpa.free(attrs_buf);
    @memset(attrs_buf, 0);
    attrs = @alignCast(@ptrCast(attrs_buf));
    try winsec.InitializeProcThreadAttributeList(attrs, 1, 0, &attrs_len);

    try winsec.UpdateProcThreadAttribute(
        attrs,
        0,
        // ProcThreadAttributeJobList
        winsec.PROC_THREAD_ATTRIBUTE_JOB_LIST,
        @as(*anyopaque, @ptrCast(@constCast(&jo))),
        @sizeOf(@TypeOf(jo)),
        null,
        null,
    );

    var child = childsec.ChildProcess.init(&.{ child_path, "6" }, gpa);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.proc_thread_attr_list = attrs;
    // CANCELLED = 1223 should be in u32, but we get then error code 199 by windows
    // @intFromEnum(winsec.Win32Error.CANCELLED);
    const expected_exit_code: u32 = 1;
                                          //
    std.debug.assert(expected_exit_code > 0);

    { // alive subprocesses block
        try child.spawn();
        const isproc_injob = try winsec.IsProcessInJob(child.id, jo);
        try std.testing.expectEqual(isproc_injob, true);
        // kill descendant processes in all cases
        defer winsec.TerminateJobObject(jo, expected_exit_code) catch {}; // does this error code make sense?

        // some work, supervision, forward debugging etc
    }

    // no surviving processes must exist (bindings exhaustive work, so defer it)
    // try checkNoProcessHasPrefix("evildescendent");

    const wait_res = try child.wait();
    switch (wait_res) {
        .Exited => |code| {
            if (code != expected_exit_code) {
                std.debug.print("child exit code: {d}\n", .{code});
                return error.NonZeroExitCode;
            }
        },
        else => |term| {
            std.debug.print("abnormal child exit: {}\n", .{term});
            return error.AbnormalChildExit;
        }
    }
}