//! Test explicit list of handles are inherited inspired by
//! https://devblogs.microsoft.com/oldnewthing/20111216-00/?p=8873.
//! There are 4 things to consider regarding inheritances:
//! - 1. object property if inheritance is enabled
//! - 2. security object to decide which object group is inherited
//!      * can not retrospectively attached to handle
//! - 3. CreateProcess property if inheritance is enabled
//! - 4. Explicit list of handles with enabled inheritance to be inherited
//!      * requires 1.+3. on all handles in inheritance list
//!      * fails with INVALID_ARGUMENT otherwise

const std = @import("std");
const sec = @import("sec");
const winsec = sec.os.win;
const childsec = sec.child;
const ossec = sec.os;

const NUM_FILES = 100;

pub fn main() !void {
    var gpa_state = std.heap.GeneralPurposeAllocator(.{ .safety = true }){};
    defer if (gpa_state.deinit() != .ok) {
        @panic("found memory leaks");
    };
    const gpa = gpa_state.allocator();
    try behavior(gpa);
}

fn behavior(gpa: std.mem.Allocator) !void {
    const tmpDir = std.testing.tmpDir;
    var tmp = tmpDir(.{});
    defer tmp.cleanup();

    var file_hs: [NUM_FILES]std.fs.File.Handle = undefined;
    {
        var file_buf: [100]u8 = undefined;
        // minimize some memory usage here
        for (file_hs, 0..) |_, i| {
            errdefer for (file_hs[0..i]) |file_hcl|
                std.os.windows.CloseHandle(file_hcl);
            const fname = try std.fmt.bufPrint(file_buf[0..], "testfile{d}", .{i});
            const file = try tmp.dir.createFile(fname, .{});
            file_hs[i] = file.handle;
        }
        defer for (file_hs) |file_h|
            std.os.windows.CloseHandle(file_h);

        for (file_hs) |file_h| {
            if (try ossec.isInheritable(file_h) == true) return error.TestError;
            try ossec.enableInheritance(file_h);
        }

        var attrs: winsec.LPPROC_THREAD_ATTRIBUTE_LIST = undefined;
        var attrs_len: winsec.SIZE_T = undefined;
        // TODO fix this
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
            winsec.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
            @as(*anyopaque, @ptrCast(@constCast(&file_hs))),
            @sizeOf(@TypeOf(file_hs)),
            null,
            null,
        );

        var it = try std.process.argsWithAllocator(gpa);
        defer it.deinit();
        _ = it.next() orelse unreachable; // skip binary name
        const child_path = it.next() orelse unreachable;

        const T = [NUM_FILES+1][ossec.handleCharSize]u8;
        var buf_handles_s  = std.mem.zeroes(T);
        var handles_s: [NUM_FILES+1][]const u8 = undefined;
        try std.testing.expectEqual(handles_s.len, file_hs.len + 1);
        try std.testing.expectEqual(handles_s.len, buf_handles_s.len);
        handles_s[0] = child_path[0..child_path.len];
        for (file_hs, 0..) |file_h, i| {
            handles_s[i+1] = try ossec.handleToString(file_h, buf_handles_s[i+1][0..]);
        }

        var child = childsec.ChildProcess.init(&handles_s, gpa);
        child.stdin_behavior = .Close;
        child.stdout_behavior = .Close;
        child.stderr_behavior = .Inherit;
        child.proc_thread_attr_list = attrs;

        try child.spawn();
        const wait_res = try child.wait();
        switch (wait_res) {
            .Exited => |exit_code| {
                if (exit_code != 0) return error.NonZeroExitCode;
            },
            else => |term| {
                std.debug.print("abnormal child exit: {}", .{term});
                return error.AbnormlChildExit;
            }
        }
    }

    { // Reopen file (or seek to start) to see result of child process
        var file_buf: [100]u8 = undefined;
        for (file_hs, 0..) |_, i| {
            errdefer for (file_hs[0..i]) |file_hcl|
                std.os.windows.CloseHandle(file_hcl);
            const fname = try std.fmt.bufPrint(file_buf[0..], "testfile{d}", .{i});
            const file = try tmp.dir.openFile(fname, .{});
            file_hs[i] = file.handle;
        }
        defer for (file_hs) |file_h|
            std.os.windows.CloseHandle(file_h);

        for (file_hs, 0..) |_, i| {
            var res_buf: [100]u8 = undefined;
            const file_rd = std.fs.File { .handle = file_hs[i] };
            const file_len = try file_rd.readAll(&res_buf);
            const expected_result = try std.fmt.bufPrint(res_buf[0..], "testfile{d}", .{i});
            std.testing.expectEqualSlices(u8, expected_result, res_buf[0..file_len]) catch {
                return error.Incorrect;
            };
        }
    }
}