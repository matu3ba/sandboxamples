const std = @import("std");
const builtin = @import("builtin");
const win = @import("os/win.zig");
const native_os = builtin.os.tag;

pub const windowsPtrDigits = 19; // log10(max(usize))
pub const unixoidPtrDigits = 10; // log10(max(u32)) + 1 for sign
pub const handleCharSize = if (native_os == .windows) windowsPtrDigits else unixoidPtrDigits;

pub fn handleToString(handle: std.posix.fd_t, buf: []u8) std.fmt.BufPrintError![]u8 {
    const handle_int =
        // handle is *anyopaque or an integer on unix-likes Kernels.
        if (native_os == .windows) @intFromPtr(handle) else handle;
    return try std.fmt.bufPrint(buf[0..], "{d}", .{handle_int});
}

pub fn stringToHandle(s_handle: []const u8) std.fmt.ParseIntError!std.posix.fd_t {
    const handle: std.posix.fd_t = if (native_os == .windows)
        @ptrFromInt(try std.fmt.parseInt(usize, s_handle, 10))
    else
        try std.fmt.parseInt(std.posix.fd_t, s_handle, 10);
    return handle;
}

const IsInheritableError = std.posix.FcntlError || win.GetHandleInformationError;

/// Is inheritence enabled or CLOEXEC not set?
pub inline fn isInheritable(handle: std.posix.fd_t) IsInheritableError!bool {
    if (native_os == .windows) {
        var handle_flags: win.DWORD = undefined;
        try win.GetHandleInformation(handle, &handle_flags);
        return handle_flags & std.os.windows.HANDLE_FLAG_INHERIT != 0;
    } else {
        const fcntl_flags = try std.posix.fcntl(handle, std.posix.F.GETFD, 0);
        return fcntl_flags & std.posix.FD_CLOEXEC == 0;
    }
}

const EnableInheritanceError = std.posix.FcntlError || std.os.windows.SetHandleInformationError;

/// Enables inheritence or sets CLOEXEC.
pub inline fn enableInheritance(handle: std.posix.fd_t) EnableInheritanceError!void {
    if (native_os == .windows) {
        try std.os.windows.SetHandleInformation(handle, std.os.windows.HANDLE_FLAG_INHERIT, 1);
    } else {
        var flags = try std.posix.fcntl(handle, std.posix.F.GETFD, 0);
        flags &= ~@as(u32, std.posix.FD_CLOEXEC);
        _ = try std.posix.fcntl(handle, std.posix.F.SETFD, flags);
    }
}

const DisableInheritanceError = std.posix.FcntlError || std.os.windows.SetHandleInformationError;

/// Disables inheritence or unsets CLOEXEC.
pub inline fn disableInheritance(handle: std.posix.fd_t) DisableInheritanceError!void {
    if (native_os == .windows) {
        try std.os.windows.SetHandleInformation(handle, std.os.windows.HANDLE_FLAG_INHERIT, 0);
    } else {
        _ = try std.posix.fcntl(handle, std.posix.F.SETFD, std.posix.FD_CLOEXEC);
    }
}
