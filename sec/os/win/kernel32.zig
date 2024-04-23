// SPDX-License-Identifier: MIT
// SPDX-SnippetCopyrightText: Zig contributors

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

pub extern "kernel32" fn GetCurrentProcess() callconv(win.WINAPI) win.HANDLE;
pub extern "kernel32" fn OpenProcessToken(proc_h: win.HANDLE, want_access: u32, token_h: *win.HANDLE) callconv(win.WINAPI) win.BOOL;
pub extern "kernel32" fn GetTokenInformation(
    token_h: win.HANDLE,
    token_info_ty: win.TokenInfo,
    token_info: ?win.LPVOID,
    token_info_len: win.DWORD,
    used_token_info_len: *win.DWORD,
) callconv(win.WINAPI) win.BOOL;

// ====checks
pub extern "kernel32" fn OpenProcess(dwDesiredAccess: win.DWORD, bInheritHandle: win.BOOL, dwProcessId: win.DWORD) callconv(win.WINAPI) ?win.HANDLE;
pub extern "kernel32" fn K32EnumProcessModules(hProcess: win.HANDLE, lphModule: *win.HMODULE, cb: win.DWORD, lpcbNeeded: *win.DWORD) callconv(win.WINAPI) win.BOOL;
pub extern "kernel32" fn K32EnumProcesses(lpidProcess: [*]win.DWORD, cb: win.DWORD, lpcbNeeded: *win.DWORD) callconv(win.WINAPI) win.BOOL;
pub extern "kernel32" fn K32GetModuleBaseNameW(hProcess: win.HANDLE, hModule: ?win.HMODULE, lpBaseName: win.LPWSTR, nSize: win.DWORD) callconv(win.WINAPI) win.BOOL;

// ====fixups
pub extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(win.WINAPI) ?win.HMODULE;
pub extern "kernel32" fn FreeLibrary(hModule: win.HMODULE) callconv(win.WINAPI) win.BOOL;

// ====security
// pub extern "kernel32" fn GetSecurityInfo(
//     handle: win.HANDLE,
//     object_ty: u32, // win.SE_OBJECT_TYPE,
//     sec_info_select: u32, // win.SECURITY_INFORMATION,
//     ppsidOwner: ?*win.PSID,
//     ppsidGroup: ?*win.PSID,
//     ppDacl: ?**win.ACL,
//     ppSacl: ?**win.ACL,
//     ppSecurityDescriptor: ?*win.PSECURITY_DESCRIPTOR,
// ) callconv(win.WINAPI) win.BOOL;

// advapi32
// pub extern "advapi32" fn GetSecurityInfo(
//     handle: ?win.HANDLE,
//     ObjectType: win.DWORD, // win.SE_OBJECT_TYPE,
//     SecurityInfo: win.DWORD,
//     ppsidOwner: [*c]win.PSID,
//     ppsidGroup: [*c]win.PSID,
//     ppDacl: [*c]win.ACL,
//     ppSacl: [*c]win.ACL,
//     ppSecurityDescriptor: [*c]win.PSECURITY_DESCRIPTOR,
// ) callconv(win.WINAPI) win.DWORD;
