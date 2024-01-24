// SPDX-License-Identifier: MIT
// SPDX-SnippetCopyrightText: Zig contributors

const std = @import("std");
const builtin = @import("builtin");
const native_arch = builtin.cpu.arch;
const LANG = @import("win/lang.zig");
const SUBLANG = @import("win/sublang.zig");

pub const kernel32 = @import("win/kernel32.zig");
pub const advapi32 = @import("win/advapi32.zig");
pub const Win32Error = @import("win/win32error.zig").Win32Error;
pub const WINAPI: std.builtin.CallingConvention = if (native_arch == .x86)
    .Stdcall
else
    .C;

pub const BOOL = i32;
pub const BYTE = u8;
pub const DWORD = u32;
pub const HANDLE = *anyopaque;
pub const HMODULE = *opaque {};
pub const LPCWSTR = [*:0]const WCHAR;
pub const LPPROC_THREAD_ATTRIBUTE_LIST = *anyopaque;
pub const LPVOID = *anyopaque;
pub const LPWSTR = [*:0]WCHAR;
pub const PSTR = [*:0]u8;
pub const PVOID = *anyopaque;
pub const PWSTR = [*:0]u16;
pub const SIZE_T = usize;
pub const WCHAR = u16;
pub const WORD = u16;
pub const va_list = *opaque {};
pub const LARGE_INTEGER = i64;
pub const ULARGE_INTEGER = u64;
pub const ULONG = u32;
pub const LONG = i32;
pub const ULONGLONG = u64;
pub const PSID = ?*opaque{};
pub const PSECURITY_DESCRIPTOR = ?*anyopaque;

pub const SECURITY_ATTRIBUTES = extern struct {
    nLength: DWORD,
    lpSecurityDescriptor: ?*anyopaque,
    bInheritHandle: BOOL,
};

pub const STARTUPINFOW = extern struct {
    cb: DWORD,
    lpReserved: ?LPWSTR,
    lpDesktop: ?LPWSTR,
    lpTitle: ?LPWSTR,
    dwX: DWORD,
    dwY: DWORD,
    dwXSize: DWORD,
    dwYSize: DWORD,
    dwXCountChars: DWORD,
    dwYCountChars: DWORD,
    dwFillAttribute: DWORD,
    dwFlags: DWORD,
    wShowWindow: WORD,
    cbReserved2: WORD,
    lpReserved2: ?*BYTE,
    hStdInput: ?HANDLE,
    hStdOutput: ?HANDLE,
    hStdError: ?HANDLE,
};

pub const PROCESS_INFORMATION = extern struct {
    hProcess: HANDLE,
    hThread: HANDLE,
    dwProcessId: DWORD,
    dwThreadId: DWORD,
};


pub const STARTUPINFOEXW = extern struct {
    lpStartupInfo: STARTUPINFOW,
    lpAttributeList: ?LPPROC_THREAD_ATTRIBUTE_LIST,
};

// zig fmt: off
pub const PROCESS_CREATION_FLAGS = enum(u32) {
    // <- gap here ->
    DEBUG_PROCESS                       = 0x0000_0001,
    DEBUG_ONLY_THIS_PROCESS             = 0x0000_0002,
    CREATE_SUSPENDED                    = 0x0000_0004,
    DETACHED_PROCESS                    = 0x0000_0008,
    CREATE_NEW_CONSOLE                  = 0x0000_0010,
    NORMAL_PRIORITY_CLASS               = 0x0000_0020,
    IDLE_PRIORITY_CLASS                 = 0x0000_0040,
    HIGH_PRIORITY_CLASS                 = 0x0000_0080,
    REALTIME_PRIORITY_CLASS             = 0x0000_0100,
    CREATE_NEW_PROCESS_GROUP            = 0x0000_0200,
    CREATE_UNICODE_ENVIRONMENT          = 0x0000_0400,
    CREATE_SEPARATE_WOW_VDM             = 0x0000_0800,
    CREATE_SHARED_WOW_VDM               = 0x0000_1000,
    CREATE_FORCEDOS                     = 0x0000_2000,
    BELOW_NORMAL_PRIORITY_CLASS         = 0x0000_4000,
    ABOVE_NORMAL_PRIORITY_CLASS         = 0x0000_8000,
    INHERIT_PARENT_AFFINITY             = 0x0001_0000,
    INHERIT_CALLER_PRIORITY             = 0x0002_0000,
    CREATE_PROTECTED_PROCESS            = 0x0004_0000,
    EXTENDED_STARTUPINFO_PRESENT        = 0x0008_0000,
    PROCESS_MODE_BACKGROUND_BEGIN       = 0x0010_0000,
    PROCESS_MODE_BACKGROUND_END         = 0x0020_0000,
    CREATE_SECURE_PROCESS               = 0x0040_0000,
    // <- gap here ->
    CREATE_BREAKAWAY_FROM_JOB           = 0x0100_0000,
    CREATE_PRESERVE_CODE_AUTHZ_LEVEL    = 0x0200_0000,
    CREATE_DEFAULT_ERROR_MODE           = 0x0400_0000,
    CREATE_NO_WINDOW                    = 0x0800_0000,
    PROFILE_USER                        = 0x1000_0000,
    PROFILE_KERNEL                      = 0x2000_0000,
    PROFILE_SERVER                      = 0x4000_0000,
    CREATE_IGNORE_SYSTEM_DEFAULT        = 0x8000_0000,
    _,
};
// zig fmt: on

pub const PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = extern struct {
    DUMMYUNIONNAME : extern union {
        Flags : DWORD,
        DUMMYSTRUCTNAME : packed struct {
            DisallowWin32kSystemCalls : u1,
            AuditDisallowWin32kSystemCalls : u1,
            DisallowFsctlSystemCalls: u1,
            AuditDisallowFsctlSystemCalls: u1,
            ReservedFlags : u28,
        },
    },
};

pub const PROCESS_MITIGATION_POLICY = enum(c_int) {
    ProcessDEPPolicy,
    ProcessASLRPolicy,
    ProcessDynamicCodePolicy,
    ProcessStrictHandleCheckPolicy,
    ProcessSystemCallDisablePolicy,
    ProcessMitigationOptionsMask,
    ProcessExtensionPointDisablePolicy,
    ProcessControlFlowGuardPolicy,
    ProcessSignaturePolicy,
    ProcessFontDisablePolicy,
    ProcessImageLoadPolicy,
    ProcessSystemCallFilterPolicy,
    ProcessPayloadRestrictionPolicy,
    ProcessChildProcessPolicy,
    ProcessSideChannelIsolationPolicy,
    ProcessUserShadowStackPolicy,
    MaxProcessMitigationPolicy
};

pub const GetProcessMitigationPolicyError = error{Unexpected};
pub fn GetProcessMitigationPolicy(
    hProcess: HANDLE,
    MitigationPolicy: PROCESS_MITIGATION_POLICY,
    lpBuffer: PVOID,
    dwLength: SIZE_T,
) GetProcessMitigationPolicyError!void {
    if (kernel32.GetProcessMitigationPolicy(hProcess, MitigationPolicy, lpBuffer, dwLength) == 0) {
        switch (kernel32.GetLastError()) {
            // .FILE_NOT_FOUND => return error.FileNotFound,
            // .PATH_NOT_FOUND => return error.FileNotFound,
            // .MOD_NOT_FOUND => return error.FileNotFound,
            else => |err| return unexpectedError(err),
        }
    }
}

pub const InitializeProcThreadAttributeListError = error{Unexpected, InsufficientBuffer};
pub fn InitializeProcThreadAttributeList(
    lpAttributeList: ?LPPROC_THREAD_ATTRIBUTE_LIST,
    dwAttributeCount: u32,
    dwFlags: u32,
    lpSize: ?*usize,
) InitializeProcThreadAttributeListError!void {
    if (kernel32.InitializeProcThreadAttributeList(lpAttributeList, dwAttributeCount, dwFlags, lpSize) == 0) {
        switch (kernel32.GetLastError()) {
            .INSUFFICIENT_BUFFER => return error.InsufficientBuffer,
            else => |err| return unexpectedError(err),
        }
    }
}

pub const DeleteProcThreadAttributeListError = error{Unexpected};
pub fn DeleteProcThreadAttributeList(
    lpAttributeList: ?LPPROC_THREAD_ATTRIBUTE_LIST,
) DeleteProcThreadAttributeListError!void {
    if (kernel32.DeleteProcThreadAttributeList(lpAttributeList) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const UpdateProcThreadAttributeError = error{NoSpaceLeft, Unexpected};
pub fn UpdateProcThreadAttribute(
    lpAttributeList: ?LPPROC_THREAD_ATTRIBUTE_LIST,
    dwFlags: u32,
    Attribute: usize,
    lpValue: ?*anyopaque,
    cbSize: usize,
    lpPreviousValue: ?*anyopaque,
    lpReturnSize: ?*usize,
) UpdateProcThreadAttributeError!void {
    if (kernel32.UpdateProcThreadAttribute(
        lpAttributeList,
        dwFlags,
        Attribute,
        lpValue,
        cbSize,
        lpPreviousValue,
        lpReturnSize,
    ) == 0) {
        switch (kernel32.GetLastError()) {
            .BAD_LENGTH => return error.NoSpaceLeft, // ThreadAttributeList too short
            else => |err| return unexpectedError(err),
        }
    }
}

// for unexpectedError
pub const FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000;
pub const FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200;
pub const LANGID = c_ushort;
inline fn MAKELANGID(p: c_ushort, s: c_ushort) LANGID {
    return (s << 10) | p;
}


/// Call this when you made a windows DLL call or something that does SetLastError
/// and you get an unexpected error.
pub fn unexpectedError(err: Win32Error) std.os.UnexpectedError {
    if (std.os.unexpected_error_tracing) {
        // 614 is the length of the longest windows error description
        var buf_wstr: [614]WCHAR = undefined;
        var buf_utf8: [614]u8 = undefined;
        const len = kernel32.FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            null,
            err,
            MAKELANGID(LANG.NEUTRAL, SUBLANG.DEFAULT),
            &buf_wstr,
            buf_wstr.len,
            null,
        );
        _ = std.unicode.utf16leToUtf8(&buf_utf8, buf_wstr[0..len]) catch unreachable;
        std.debug.print("error.Unexpected: GetLastError({}): {s}\n", .{ @intFromEnum(err), buf_utf8[0..len] });
        std.debug.dumpCurrentStackTrace(@returnAddress());
    }
    return error.Unexpected;
}

const PROC_THREAD_ATTRIBUTE_NUMBER   = 0x0000FFFF;
const PROC_THREAD_ATTRIBUTE_THREAD   = 0x00010000; // Attribute may be used with thread creation
const PROC_THREAD_ATTRIBUTE_INPUT    = 0x00020000; // Attribute is input only
const PROC_THREAD_ATTRIBUTE_ADDITIVE = 0x00040000; // Attribute may be "accumulated," e.g. bitmasks, counters, etc.

pub fn ProcThreadAttributeValue(
    comptime number: u32,
    comptime thread: bool,
    comptime input: bool,
    comptime additive: bool,
) u32 {
    const s1 = number & PROC_THREAD_ATTRIBUTE_NUMBER;
    const s2 = if (thread != false) PROC_THREAD_ATTRIBUTE_THREAD else 0;
    const s3 = if (input != false) PROC_THREAD_ATTRIBUTE_INPUT else 0;
    const s4 = if (additive != false) PROC_THREAD_ATTRIBUTE_ADDITIVE else 0;
    return s1 | s2 | s3 | s4;
}

// zig fmt: off
pub const PROC_THREAD_ATTRIBUTE_NUM = enum(u32) {
    ProcThreadAttributeParentProcess                = 0,
    // < gap >
    ProcThreadAttributeHandleList                   = 2,
    // start >= _WIN32_WINNT_WIN7
    ProcThreadAttributeGroupAffinity                = 3,
    ProcThreadAttributePreferredNode                = 4,
    ProcThreadAttributeIdealProcessor               = 5,
    ProcThreadAttributeUmsThread                    = 6,
    ProcThreadAttributeMitigationPolicy             = 7,
    // < gap >
    // endof >= _WIN32_WINNT_WIN7
    ProcThreadAttributeSecurityCapabilities         = 9,  // >= _WIN32_WINNT_WIN8
    // < gap >
    ProcThreadAttributeProtectionLevel              = 11,
    // < gap >
    // start >= _WIN32_WINNT_WINTHRESHOLD
    ProcThreadAttributeJobList                      = 13,
    ProcThreadAttributeChildProcessPolicy           = 14,
    ProcThreadAttributeAllApplicationPackagesPolicy = 15,
    ProcThreadAttributeWin32kFilter                 = 16,
    // endof >= _WIN32_WINNT_WINTHRESHOLD
    ProcThreadAttributeSafeOpenPromptOriginClaim    = 17, // >= NTDDI_WIN10_RS1
    ProcThreadAttributeDesktopAppPolicy             = 18, // >= NTDDI_WIN10_RS2
    // < gap >
    ProcThreadAttributePseudoConsole                = 22, // >= NTDDI_WIN10_RS5
    // < gap >
    ProcThreadAttributeMitigationAuditPolicy        = 24, // >= NTDDI_WIN10_MN
};
pub const PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeParentProcess), false, true, false
);

/// If handles in list not inheritable, CreateProcess* errors with INVALID_PARAMETER.
pub const PROC_THREAD_ATTRIBUTE_HANDLE_LIST = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeHandleList), false, true, false
);
pub const PROC_THREAD_ATTRIBUTE_GROUP_AFFINITY = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeGroupAffinity), true, true, false
);
pub const PROC_THREAD_ATTRIBUTE_PREFERRED_NODE = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributePreferredNode), false, true, false
);
pub const PROC_THREAD_ATTRIBUTE_IDEAL_PROCESSOR = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeIdealProcessor), true, true, false
);
pub const PROC_THREAD_ATTRIBUTE_UMS_THREAD = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeUmsThread), true, true, false
);
pub const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeMitigationPolicy), false, true, false
);
pub const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeSecurityCapabilities), false, true, false
);
pub const PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeProtectionLevel), false, true, false
);
pub const PROC_THREAD_ATTRIBUTE_JOB_LIST = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeJobList), false, true, false
);
pub const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeChildProcessPolicy), false, true, false
);
pub const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeAllApplicationPackagesPolicy), false, true, false
);
pub const PROC_THREAD_ATTRIBUTE_WIN32K_FILTER = ProcThreadAttributeValue(
    @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeWin32kFilter), false, true, false
);

pub const PROC_THREAD_ATTRIBUTE_DESKTOP_APP_POLICY = val: {
    if (!builtin.target.os.version_range.windows.min.isAtLeast(.win10_rs2))
        @compileError("Mitigation not available for target");
    break :val ProcThreadAttributeValue(
        @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeDesktopAppPolicy), false, true, false
    );
};

pub const PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE = val: {
    if (!builtin.target.os.version_range.windows.min.isAtLeast(.win10_rs5))
        @compileError("Mitigation not available for target");
    break :val ProcThreadAttributeValue(
        @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributePseudoConsole), false, true, false
    );
};

const PROC_THREAD_ATTRIBUTE_MITIGATION_AUDIT_POLICY = val: {
    if (!builtin.target.os.version_range.windows.min.isAtLeast(.win10_mn))
        @compileError("Mitigation not available for target");
    break :val ProcThreadAttributeValue(
        @intFromEnum(PROC_THREAD_ATTRIBUTE_NUM.ProcThreadAttributeMitigationAuditPolicy), false, true, false
    );
};

pub const PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE = struct {
    pub const MASK       =        (0x00000003 << 28);
    pub const DEFER      =        (0x00000000 << 28);
    pub const ALWAYS_ON  =        (0x00000001 << 28);
    pub const ALWAYS_OFF =        (0x00000002 << 28);
    pub const RESERVED   =        (0x00000003 << 28);
};
// zig fmt: on


pub const GetHandleInformationError = error{Unexpected};

pub fn GetHandleInformation(h: HANDLE, flags: *DWORD) GetHandleInformationError!void {
    if (kernel32.GetHandleInformation(h, flags) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

// ====fixups
pub const LoadLibraryError = error{
    FileNotFound,
    Unexpected,
    InitFailed,
    OutOfVirtualMemory,
};

pub fn LoadLibraryW(lpLibFileName: [*:0]const u16) LoadLibraryError!HMODULE {
    return kernel32.LoadLibraryW(lpLibFileName) orelse {
        switch (kernel32.GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .PATH_NOT_FOUND => return error.FileNotFound,
            .MOD_NOT_FOUND => return error.FileNotFound,
            .DLL_INIT_FAILED => return error.InitFailed,
            .NOT_ENOUGH_MEMORY => return error.OutOfVirtualMemory,
            else => |err| return unexpectedError(err),
        }
    };
}

pub fn FreeLibrary(hModule: HMODULE) void {
    std.debug.assert(kernel32.FreeLibrary(hModule) != 0);
}

pub const CreateProcessError = error{
    FileNotFound,
    AccessDenied,
    InvalidName,
    NameTooLong,
    InvalidExe,
    Unexpected,
};

pub fn CreateProcessW(
    lpApplicationName: ?LPCWSTR,
    lpCommandLine: ?LPWSTR,
    lpProcessAttributes: ?*SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*SECURITY_ATTRIBUTES,
    bInheritHandles: BOOL,
    dwCreationFlags: DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?LPCWSTR,
    lpStartupInfo: *STARTUPINFOW,
    lpProcessInformation: *PROCESS_INFORMATION,
) CreateProcessError!void {
    if (kernel32.CreateProcessW(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
    ) == 0) {
        switch (kernel32.GetLastError()) {
            .FILE_NOT_FOUND => return error.FileNotFound,
            .PATH_NOT_FOUND => return error.FileNotFound,
            .ACCESS_DENIED => return error.AccessDenied,
            .INVALID_PARAMETER => unreachable,
            .NOACCESS => unreachable,
            .INVALID_NAME => return error.InvalidName,
            .FILENAME_EXCED_RANGE => return error.NameTooLong,
            // These are all the system errors that are mapped to ENOEXEC by
            // the undocumented _dosmaperr (old CRT) or __acrt_errno_map_os_error
            // (newer CRT) functions. Their code can be found in crt/src/dosmap.c (old SDK)
            // or urt/misc/errno.cpp (newer SDK) in the Windows SDK.
            .BAD_FORMAT,
            .INVALID_STARTING_CODESEG, // MIN_EXEC_ERROR in errno.cpp
            .INVALID_STACKSEG,
            .INVALID_MODULETYPE,
            .INVALID_EXE_SIGNATURE,
            .EXE_MARKED_INVALID,
            .BAD_EXE_FORMAT,
            .ITERATED_DATA_EXCEEDS_64k,
            .INVALID_MINALLOCSIZE,
            .DYNLINK_FROM_INVALID_RING,
            .IOPL_NOT_ENABLED,
            .INVALID_SEGDPL,
            .AUTODATASEG_EXCEEDS_64k,
            .RING2SEG_MUST_BE_MOVABLE,
            .RELOC_CHAIN_XEEDS_SEGLIM,
            .INFLOOP_IN_RELOC_CHAIN, // MAX_EXEC_ERROR in errno.cpp
            // This one is not mapped to ENOEXEC but it is possible, for example
            // when calling CreateProcessW on a plain text file with a .exe extension
            .EXE_MACHINE_TYPE_MISMATCH,
            => return error.InvalidExe,
            else => |err| return unexpectedError(err),
        }
    }
}

pub fn CreateJobObject(lpJobAttributes: ?*SECURITY_ATTRIBUTES, lpName: ?LPCWSTR) HANDLE {
    return kernel32.CreateJobObjectW(lpJobAttributes, lpName);
}

pub const SetInformationJobObjectError = error{Unexpected};

pub fn SetInformationJobObject(
    hJob: HANDLE,
    jobObjectInformationClass: JobObjectInformationClass,
    lpJobObjectInformation: LPVOID,
    cbJobObjectInformationLength: DWORD,
) SetInformationJobObjectError!void {
    if (kernel32.SetInformationJobObject(hJob, jobObjectInformationClass, lpJobObjectInformation, cbJobObjectInformationLength) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const IsProcessInJobError = error{Unexpected};

pub fn IsProcessInJob(
    hProcess: HANDLE,
    hJob: HANDLE,
) IsProcessInJobError!bool {
    var Result: BOOL = undefined;
    if (kernel32.IsProcessInJob(hProcess, hJob, &Result) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
        return Result != 0;
}

pub const TerminateJobObjectError = error{Unexpected};

/// uExitCode should be smaller than than 1223. As example, the process may
/// return (AUTODATASEG_EXCEEDS_64k/199) if you use (CANCELLED/1223).
pub fn TerminateJobObject(
    hJob: HANDLE,
    uExitCode: u32,
) TerminateJobObjectError!void {
    if (kernel32.TerminateJobObject(hJob, uExitCode) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

// zig fmt: off
pub const PROCESS_ACCESS_RIGHTS = enum(u32) {
    TERMINATE =                 0x0001,
    CREATE_THREAD =             0x0002,
    SET_SESSIONID =             0x0004,
    VM_OPERATION =              0x0008,
    VM_READ =                   0x0010,
    VM_WRITE =                  0x0020,
    DUP_HANDLE =                0x0040,
    CREATE_PROCESS =            0x0080,
    SET_QUOTA =                 0x0100,
    SET_INFORMATION =           0x0200,
    QUERY_INFORMATION =         0x0400,
    SUSPEND_RESUME =            0x0800,
    QUERY_LIMITED_INFORMATION = 0x1000,
    SET_LIMITED_INFORMATION =   0x2000,
};
// zig fmt: on


pub const OpenProcessError = error{
    AccessDenied,
    Unexpected,
};

/// dwDesiredAccess uses PROCESS_ACCESS_RIGHTS
pub fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: bool, dwProcessId: DWORD) OpenProcessError!HANDLE {
    const res = kernel32.OpenProcess(dwDesiredAccess, @intFromBool(bInheritHandle), dwProcessId);
    if (res == null) {
        switch (kernel32.GetLastError()) {
            .ACCESS_DENIED => return error.AccessDenied,
            .NOACCESS => return error.AccessDenied,
            else => |err| return unexpectedError(err),
        }
    }
    return res.?;
}


pub const EnumProcessModulesError = error{
    Unexpected,
    PartialCopy,
};

pub fn EnumProcessModules(hProcess: HANDLE, lphModule: *HMODULE, cb: DWORD, lpcbNeeded: *DWORD) EnumProcessModulesError!void {
    if (kernel32.K32EnumProcessModules(hProcess, lphModule, cb, lpcbNeeded) == 0) {
        switch (kernel32.GetLastError()) {
            .PARTIAL_COPY => return error.PartialCopy,
            else => |err| return unexpectedError(err),
        }
    }
}

pub const EnumProcessesError = error{Unexpected};

pub fn EnumProcesses(lpidProcess: [*]DWORD, cb: DWORD, lpcbNeeded: *DWORD) EnumProcessesError!void {
    if (kernel32.K32EnumProcesses(lpidProcess, cb, lpcbNeeded) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
}

pub const GetModuleBaseNameError = error{
    AccessDenied,
    Unexpected,
};

pub fn GetModuleBaseName(hProcess: HANDLE, hModule: ?HMODULE, lpBaseName: LPWSTR, nSize: DWORD) GetModuleBaseNameError!void {
    if (kernel32.K32GetModuleBaseNameW(hProcess, hModule, lpBaseName, nSize) == 0) {
        switch (kernel32.GetLastError()) {
            .NOACCESS => return error.AccessDenied,
            else => |err| return unexpectedError(err),
        }
    }
}

pub const JOBOBJECT_BASIC_LIMIT_INFORMATION = extern struct {
    PerProcessUserTimeLimit: LARGE_INTEGER,
    PerJobUserTimeLimit: LARGE_INTEGER,
    LimitFlags: DWORD,
    MinimumWorkingSetSize: SIZE_T,
    MaximumWorkingSetSize: SIZE_T,
    ActiveProcessLimit: DWORD,
    Affinity: *ULONG,
    PriorityClass: DWORD,
    SchedulingClass: DWORD,
};

pub const IO_COUNTERS = extern struct {
    ReadOperationCount: ULONGLONG,
    WriteOperationCount: ULONGLONG,
    OtherOperationCount: ULONGLONG,
    ReadTransferCount: ULONGLONG,
    WriteTransferCount: ULONGLONG,
    OtherTransferCount: ULONGLONG,
};

pub const JOBOBJECT_EXTENDED_LIMIT_INFORMATION = extern struct {
    BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION,
    IoInfo: IO_COUNTERS,
    ProcessMemoryLimit: SIZE_T,
    JobMemoryLimit: SIZE_T,
    PeakProcessMemoryUsed: SIZE_T,
    PeakJobMemoryUsed: SIZE_T,
};

pub const JOB_OBJECT_LIMIT = enum(u32) {
    // basic limits
    WORKINGSET = 0x00000001,
    PROCESS_TIME = 0x00000002,
    JOB_TIME = 0x00000004,
    ACTIVE_PROCESS = 0x00000008,
    AFFINITY = 0x00000010,
    PRIORITY_CLASS = 0x00000020,
    PRESERVE_JOB_TIME = 0x00000040,
    SCHEDULING_CLASS = 0x00000080,
    // extended limits
    PROCESS_MEMORY = 0x00000100,
    JOB_MEMORY = 0x00000200, // alias for JOB_MEMORY_HIGH
    DIE_ON_UNHANDLED_EXCEPTION = 0x00000400,
    BREAKAWAY_OK = 0x00000800,
    SILENT_BREAKAWAY_OK = 0x00001000,
    KILL_ON_JOB_CLOSE = 0x00002000,
    SUBSET_AFFINITY = 0x00004000,
    JOB_MEMORY_LOW = 0x00008000,
    // notification limits
    JOB_READ_BYTES = 0x00010000,
    JOB_WRITE_BYTES = 0x00020000,
    RATE_CONTROL = 0x00040000, // alias for CPU_RATE_CONTROL
    IO_RATE_CONTROL = 0x00080000,
    NET_RATE_CONTROL = 0x00100000,
    _,
};

pub const JobObjectInformationClass = enum(u32) {
    BasicAccountingInformation = 1,
    BasicLimitInformation = 2,
    BasicProcessIdList,
    BasicUIRestrictions,
    SecurityLimitInformation = 5,  // deprecated
    EndOfJobTimeInformation,
    AssociateCompletionPortInformation,
    BasicAndIoAccountingInformation,
    ExtendedLimitInformation,
    JobSetInformation = 10,
    GroupInformation,
    NotificationLimitInformation,
    LimitViolationInformation,
    GroupInformationEx,
    CpuRateControlInformation = 15,
    CompletionFilter,
    CompletionCounter,
    FreezeInformation,
    ExtendedAccountingInformation,
    WakeInformation = 20,
    BackgroundInformation,
    SchedulingRankBiasInformation,
    TimerVirtualizationInformation,
    CycleTimeNotification,
    ClearEvent = 25,
    InterferenceInformation,
    ClearPeakJobMemoryUsed,
    MemoryUsageInformation,
    SharedCommit,
    ContainerId = 30,
    IoRateControlInformation,
    NetRateControlInformation,
    NotificationLimitInformation2,
    LimitViolationInformation2,
    CreateSilo = 35,
    SiloBasicInformation,
    SiloRootDirectory,
    ServerSiloBasicInformation,
    ServerSiloUserSharedData,
    SiloInitialize = 40,
    ServerSiloRunningState,
    IoAttribution,
    MemoryPartitionInformation,
    ContainerTelemetryId,
    SiloSystemRoot = 45,
    EnergyTrackingState,
    ThreadImpersonationInformation,
    IoPriorityLimit,
    PagePriorityLimit = 49,
    _,
};

/// Returns pseudo-handle to current process. No need to close this handle.
pub fn GetCurrentProcess() HANDLE {
    return kernel32.GetCurrentProcess();
}

// zig fmt: off
pub const TOKEN_ACCESS = enum(u32) {
    ASSIGN_PRIMARY    = 0x00000001,
    DUPLICATE         = 0x00000002,
    IMPERSONATE       = 0x00000004,
    QUERY             = 0x00000008,
    QUERY_SOURCE      = 0x00000010,
    ADJUST_PRIVILEGES = 0x00000020,
    ADJUST_GROUPS     = 0x00000040,
    ADJUST_DEFAULT    = 0x00000080,
    ADJUST_SESSIONID  = 0x00000100,
    // <gap>
    DELETE            = 0x00010000,
    READ_CONTROL      = 0x00020000,
    WRITE_DAC         = 0x00040000,
    WRITE_OWNER       = 0x00080000,
    SYNCHRONIZE       = 0x00100000,
    // <gap>
    SYSTEM_SECURITY   = 0x01000000,
    MAXIMUM_ALLOWED   = 0x02000000,
    // <gap>
    GENERIC_ALL       = 0x10000000,
    GENERIC_EXECUTE   = 0x20000000,
    GENERIC_WRITE     = 0x40000000,
    GENERIC_READ      = 0x80000000,
};
// zig fmt: on

pub const OpenProcessTokenError = error { Unexpected };

pub fn OpenProcessToken(proc_h: HANDLE, want_access: u32) OpenProcessTokenError!HANDLE {
    var token_h: HANDLE = undefined;
    if (kernel32.OpenProcessToken(proc_h, want_access, &token_h) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return token_h;
}

// TOKEN_INFORMATION_CLASS
pub const TokenInfo = enum(c_uint) {
    User = 1,
    Groups,
    Privileges,
    Owner,
    PrimaryGroup,
    DefaultDacl,
    Source,
    Type,
    ImpersonationLevel,
    Statistics,
    RestrictedSids,
    SessionId,
    GroupsAndPrivileges,
    SessionReference,
    SandBoxInert,
    AuditPolicy,
    Origin,
    ElevationType,
    LinkedToken,
    Elevation,
    HasRestrictions,
    AccessInformation,
    VirtualizationAllowed,
    VirtualizationEnabled,
    IntegrityLevel,
    UIAccess,
    MandatoryPolicy,
    LogonSid,
    IsAppContainer,
    Capabilities,
    AppContainerSid,
    AppContainerNumber,
    UserClaimAttributes,
    DeviceClaimAttributes,
    RestrictedUserClaimAttributes,
    RestrictedDeviceClaimAttributes,
    DeviceGroups,
    RestrictedDeviceGroups,
    SecurityAttributes,
    IsRestricted,
    ProcessTrustLevel,
    PrivateNameSpace,
    SingletonAttributes,
    BnoIsolation,
    ChildProcessFlags,
    IsLessPrivilegedAppContainer,
    IsSandboxed,
    OriginatingProcessTrustLevel,
};

pub const GetTokenInformationError = error { Unexpected };

// TODO can we omit used_token_info_len and only return token_info?
pub fn GetTokenInformation(
    token_h: HANDLE,
    token_info_ty: TokenInfo,
    token_info: ?LPVOID,
    token_info_len: DWORD,
) GetTokenInformationError!DWORD {
    var used_token_info_len: DWORD = undefined;
    if (kernel32.GetTokenInformation(
            token_h,
            token_info_ty,
            token_info,
            token_info_len,
            &used_token_info_len,
    ) == 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return used_token_info_len;
}

pub const TOKEN_ELEVATION = extern struct {
    TokenIsElevated: DWORD,
};

pub const SE_OBJECT_TYPE = enum(u32) {
    UNKNOWN_OBJECT_TYPE = 0,
    FILE_OBJECT = 1,
    SERVICE = 2,
    PRINTER = 3,
    REGISTRY_KEY = 4,
    LMSHARE = 5,
    KERNEL_OBJECT = 6,
    WINDOW_OBJECT = 7,
    DS_OBJECT = 8,
    DS_OBJECT_ALL = 9,
    PROVIDER_DEFINED_OBJECT = 10,
    WMIGUID_OBJECT = 11,
    REGISTRY_WOW64_32KEY = 12,
    REGISTRY_WOW64_64KEY = 13,
};

// zig fmt: off
pub const SECURITY_INFORMATION = enum(u32) {
    OWNER               =  0x00000001,
    GROUP               =  0x00000002,
    DACL                =  0x00000004,
    SACL                =  0x00000008,
    LABEL               =  0x00000010,
    ATTRIBUTE           =  0x00000020,
    SCOPE               =  0x00000040,
    PROCESS_TRUST_LABEL =  0x00000080,
    ACCESS_FILTER       =  0x00000100,
    // <gap>
    BACKUP              =  0x00010000,
    // <gap>
    UNPROTECTED_SACL    =  0x10000000,
    UNPROTECTED_DACL    =  0x20000000,
    PROTECTED_SACL      =  0x40000000,
    PROTECTED_DACL      =  0x80000000,
    _,
};
// zig fmt: on

pub const ACL = extern struct {
    AclRevision: BYTE,
    Sbz1: BYTE,
    AclSize: WORD,
    AceCount: WORD,
    Sbz2: WORD,
};

// pub const SecurityInfo = struct {
//     ppsidOwner: PSID,
//     ppsidGroup: PSID,
//     ppDacl: *ACL,
//     ppSacl: *ACL,
//     ppSecurityDescriptor: PSECURITY_DESCRIPTOR,
// };
//
// pub const GetSecurityInfoError = error { Unexpected };
//
// pub fn GetSecurityInfo(
//     handle: HANDLE,
//     object_ty: SE_OBJECT_TYPE,
//     sec_info_select: SECURITY_INFORMATION,
// ) GetSecurityInfoError!SecurityInfo {
//     var sec_info: SecurityInfo = undefined;
//     if (kernel32.GetSecurityInfo(
//         handle,
//         object_ty,
//         sec_info_select,
//         &sec_info.ppsidOwner,
//         &sec_info.ppsidGroup,
//         &sec_info.ppDacl,
//         &sec_info.ppSacl,
//         &sec_info.ppSecurityDescriptor,
//     ) != 0) {
//         switch (kernel32.GetLastError()) {
//             else => |err| return unexpectedError(err),
//         }
//     }
//     return sec_info;
// }

pub const GetSecurityInfoError = error { Unexpected };

pub const SecurityInfo = struct {
    sid_owner: ?*PSID,
    sid_group: ?*PSID,
    dacl: ?*?*ACL,
    sacl: ?*?*ACL,
    sec_descr: ?*PSECURITY_DESCRIPTOR,
};

pub fn GetSecurityInfo(
    handle: ?HANDLE,
    object_ty: SE_OBJECT_TYPE,
    secinfo_sel: DWORD,
) GetSecurityInfoError!SecurityInfo {
    var secinfo: SecurityInfo = .{
        .sid_owner = null,
        .sid_group = null,
        .dacl = null,
        .sacl = null,
        .sec_descr = null,
    };
    if (advapi32.GetSecurityInfo(
        handle,
        object_ty,
        secinfo_sel,
        @ptrCast(&secinfo.sid_owner),
        @ptrCast(&secinfo.sid_group),
        @ptrCast(&secinfo.dacl),
        @ptrCast(&secinfo.sacl),
        @ptrCast(&secinfo.sec_descr),
    ) != 0) {
        switch (kernel32.GetLastError()) {
            else => |err| return unexpectedError(err),
        }
    }
    return secinfo;
}