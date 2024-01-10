const std = @import("std");
const builtin = @import("builtin");

pub const win = @import("os/win.zig");
pub const windowsPtrDigits = 19; // log10(max(usize))
pub const unixoidPtrDigits = 10; // log10(max(u32)) + 1 for sign
pub const handleCharSize = if (builtin.target.os.tag == .windows) windowsPtrDigits else unixoidPtrDigits;

pub fn handleToString(handle: std.os.fd_t, buf: []u8) std.fmt.BufPrintError![]u8 {
    const handle_int =
        // handle is *anyopaque or an integer on unix-likes Kernels.
        if (builtin.target.os.tag == .windows) @intFromPtr(handle) else handle;
    return try std.fmt.bufPrint(buf[0..], "{d}", .{handle_int});
}

pub fn stringToHandle(s_handle: []const u8) std.fmt.ParseIntError!std.os.fd_t {
    const handle: std.os.fd_t = if (builtin.target.os.tag == .windows)
        @ptrFromInt(try std.fmt.parseInt(usize, s_handle, 10))
    else
        try std.fmt.parseInt(std.os.fd_t, s_handle, 10);
    return handle;
}

const IsInheritableError = std.os.FcntlError || win.GetHandleInformationError;

/// Is inheritence enabled or CLOEXEC not set?
pub inline fn isInheritable(handle: std.os.fd_t) IsInheritableError!bool {
    if (builtin.os.tag == .windows) {
        var handle_flags: win.DWORD = undefined;
        try win.GetHandleInformation(handle, &handle_flags);
        return handle_flags & std.os.windows.HANDLE_FLAG_INHERIT != 0;
    } else {
        const fcntl_flags = try std.os.fcntl(handle, std.os.F.GETFD, 0);
        return fcntl_flags & std.os.FD_CLOEXEC == 0;
    }
}

const EnableInheritanceError = std.os.FcntlError || std.os.windows.SetHandleInformationError;

/// Enables inheritence or sets CLOEXEC.
pub inline fn enableInheritance(handle: std.os.fd_t) EnableInheritanceError!void {
    if (builtin.os.tag == .windows) {
        try std.os.windows.SetHandleInformation(handle, std.os.windows.HANDLE_FLAG_INHERIT, 1);
    } else {
        var flags = try std.os.fcntl(handle, std.os.F.GETFD, 0);
        flags &= ~@as(u32, std.os.FD_CLOEXEC);
        _ = try std.os.fcntl(handle, std.os.F.SETFD, flags);
    }
}

const DisableInheritanceError = std.os.FcntlError || std.os.windows.SetHandleInformationError;

/// Disables inheritence or unsets CLOEXEC.
pub inline fn disableInheritance(handle: std.os.fd_t) DisableInheritanceError!void {
    if (builtin.os.tag == .windows) {
        try std.os.windows.SetHandleInformation(handle, std.os.windows.HANDLE_FLAG_INHERIT, 0);
    } else {
        _ = try std.os.fcntl(handle, std.os.F.SETFD, std.os.FD_CLOEXEC);
    }
}