//! Applying process mitigation to newly started process.
//! https://learn.microsoft.com/en-us/windows/security/threat-protection/overview-of-threat-mitigations-in-windows-10
//! - PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE

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

fn behavior(gpa: std.mem.Allocator) !void {
    const mitigation_policy: winsec.DWORD = winsec.PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE.ALWAYS_ON;
    var attrs: winsec.LPPROC_THREAD_ATTRIBUTE_LIST = undefined;
    var attrs_len: winsec.SIZE_T = undefined;
    try std.testing.expectError(error.InsufficientBuffer, winsec.InitializeProcThreadAttributeList(null, 1, 0, &attrs_len));
    var attrs_buf: []u8 = undefined;
    attrs_buf = try gpa.alloc(u8, attrs_len);
    defer gpa.free(attrs_buf);
    @memset(attrs_buf, 0);
    attrs = @alignCast(@ptrCast(attrs_buf.ptr));
    try winsec.InitializeProcThreadAttributeList(attrs, 1, 0, &attrs_len);

    try winsec.UpdateProcThreadAttribute(
        attrs,
        0,
        winsec.PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
        @constCast(&mitigation_policy),
        @sizeOf(@TypeOf(mitigation_policy)),
        null,
        null,
    );

    var it = try std.process.argsWithAllocator(gpa);
    defer it.deinit();
    _ = it.next() orelse unreachable; // skip binary name
    const child_path = it.next() orelse unreachable;

    var child = childsec.ChildProcess.init(&.{ child_path }, gpa);
    child.stdin_behavior = .Close;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    child.proc_thread_attr_list = attrs;

    try child.spawn();
    const wait_res = try child.wait();

    switch (wait_res) {
        .Exited => |code| {
            if (code != 0) return error.NonZeroExitCode;
        },
        else => |term| {
            std.debug.print("abnormal child exit: {}", .{term});
            return error.AbnormalChildExit;
        }
    }
}