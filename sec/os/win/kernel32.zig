const win = @import("../win.zig");

pub extern "kernel32" fn FormatMessageW(dwFlags: win.DWORD, lpSource: ?win.LPVOID, dwMessageId: win.Win32Error, dwLanguageId: win.DWORD, lpBuffer: [*]u16, nSize: win.DWORD, Arguments: ?*win.va_list) callconv(win.WINAPI) win.DWORD;
pub extern "kernel32" fn GetLastError() callconv(win.WINAPI) win.Win32Error;

pub extern "kernel32" fn GetProcessMitigationPolicy(
    hProcess: win.HANDLE,
    MitigationPolicy: win.PROCESS_MITIGATION_POLICY,
    lpBuffer: win.PVOID,
    dwLength: win.SIZE_T,
) callconv(win.WINAPI) win.BOOL;

pub extern "kernel32" fn InitializeProcThreadAttributeList(
    lpAttributeList: ?win.LPPROC_THREAD_ATTRIBUTE_LIST,
    dwAttributeCount: u32,
    dwFlags: u32,
    lpSize: ?*usize,
) callconv(win.WINAPI) win.BOOL;

pub extern "kernel32" fn DeleteProcThreadAttributeList(
    lpAttributeList: ?win.LPPROC_THREAD_ATTRIBUTE_LIST,
) callconv(win.WINAPI) void;

pub extern "kernel32" fn UpdateProcThreadAttribute(
    lpAttributeList: ?win.LPPROC_THREAD_ATTRIBUTE_LIST,
    dwFlags: u32,
    Attribute: usize,
    lpValue: ?*anyopaque,
    cbSize: usize,
    lpPreviousValue: ?*anyopaque,
    lpReturnSize: ?*usize,
) callconv(win.WINAPI) win.BOOL;

pub extern "kernel32" fn CreateProcessW(
    lpApplicationName: ?win.LPCWSTR,
    lpCommandLine: ?win.LPWSTR,
    lpProcessAttributes: ?*win.SECURITY_ATTRIBUTES,
    lpThreadAttributes: ?*win.SECURITY_ATTRIBUTES,
    bInheritHandles: win.BOOL,
    dwCreationFlags: win.DWORD,
    lpEnvironment: ?*anyopaque,
    lpCurrentDirectory: ?win.LPCWSTR,
    lpStartupInfo: *win.STARTUPINFOW,
    lpProcessInformation: *win.PROCESS_INFORMATION,
) callconv(win.WINAPI) win.BOOL;


pub extern "kernel32" fn GetHandleInformation(hObject: win.HANDLE, dwFlags: *win.DWORD) callconv(win.WINAPI) win.BOOL;

pub extern "kernel32" fn CreateJobObjectW(lpJobAttributes: ?*win.SECURITY_ATTRIBUTES, lpName: ?win.LPCWSTR) callconv(win.WINAPI) win.HANDLE;
pub extern "kernel32" fn SetInformationJobObject(
    hJob: win.HANDLE,
    jobObjectInformationClass: win.JobObjectInformationClass,
    lpJobObjectInformation: win.LPVOID,
    cbJobObjectInformationLength: win.DWORD,
) callconv(win.WINAPI) win.BOOL;
pub extern "kernel32" fn IsProcessInJob(ProcessHandle: win.HANDLE, JobHandle: win.HANDLE, Result: *win.BOOL) callconv(win.WINAPI) win.BOOL;
pub extern "kernel32" fn TerminateJobObject(hJob: win.HANDLE, uExitCode: u32) callconv(win.WINAPI) win.BOOL;

// ====checks
pub extern "kernel32" fn OpenProcess(dwDesiredAccess: win.DWORD, bInheritHandle: win.BOOL, dwProcessId: win.DWORD) callconv(win.WINAPI) ?win.HANDLE;
pub extern "kernel32" fn K32EnumProcessModules(hProcess: win.HANDLE, lphModule: *win.HMODULE, cb: win.DWORD, lpcbNeeded: *win.DWORD) callconv(win.WINAPI) win.BOOL;
pub extern "kernel32" fn K32EnumProcesses(lpidProcess: [*]win.DWORD, cb: win.DWORD, lpcbNeeded: *win.DWORD) callconv(win.WINAPI) win.BOOL;
pub extern "kernel32" fn K32GetModuleBaseNameW(hProcess: win.HANDLE, hModule: ?win.HMODULE, lpBaseName: win.LPWSTR, nSize: win.DWORD) callconv(win.WINAPI) win.BOOL;

// ====fixups
pub extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(win.WINAPI) ?win.HMODULE;
pub extern "kernel32" fn FreeLibrary(hModule: win.HMODULE) callconv(win.WINAPI) win.BOOL;