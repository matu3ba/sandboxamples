const std = @import("std");
const sec = @import("sec");
const ossec = sec.os;
const winsec = sec.os.win;

pub fn main() !void {
    try behavior();
    std.process.exit(0);
}

fn behavior() !void {
    const SYSCALL_DISABLE_POLICY = winsec.PROCESS_MITIGATION_POLICY;
    var effectice_policy: winsec.PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY = undefined;
    const process_handle = std.os.windows.kernel32.GetCurrentProcess();
    try winsec.GetProcessMitigationPolicy(
        process_handle,
        SYSCALL_DISABLE_POLICY.ProcessSystemCallDisablePolicy,
        &effectice_policy,
        @sizeOf(@TypeOf(effectice_policy)),
    );

    if (effectice_policy.DUMMYUNIONNAME.DUMMYSTRUCTNAME.DisallowWin32kSystemCalls != 1) {
        return error.NoWin32Syscalls;
    }
    const L = std.unicode.utf8ToUtf16LeStringLiteral;

    const ntdll_mod = try winsec.LoadLibraryW(L("ntdll.dll"));
    winsec.FreeLibrary(ntdll_mod);
    try std.testing.expectError(error.InitFailed, winsec.LoadLibraryW(L("USER32.dll")));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("USER32.dll")));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("USER32.dll")));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("USER32.dll")));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("USER32.dll")));

    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("gdi32full.dll")));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("GDI32.dll")));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("api-ms-win-gdi-internal-uap-l1-1-0.dll")));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("USER32.dll")));

    // SPDX-SnippetBegin
    // SPDX-License-Identifier: MIT
    // SPDX-SnippetCopyrightText: 2019 Matthieu Buffet, 2024 Jan Philipp Hafer

    // checking gdi32full.dll dependencies
    _ = try winsec.LoadLibraryW(L("msvcp_win.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-crt-string-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-crt-runtime-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-crt-private-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-string-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-localization-l1-2-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-heap-l2-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-rtlsupport-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-libraryloader-l1-2-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-sysinfo-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-memory-l1-1-1.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-errorhandling-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-processenvironment-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-file-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-handle-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-registry-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-file-l1-2-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-synch-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-heap-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-file-l2-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-memory-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-threadpool-l1-2-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-processthreads-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-debug-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-string-l2-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-security-base-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-processthreads-l1-1-1.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-profile-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-interlocked-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-kernel32-legacy-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-heap-obsolete-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-string-obsolete-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-stringansi-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("ntdll.dll"));
    _ = try winsec.LoadLibraryW(L("win32u.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-delayload-l1-1-1.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-delayload-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-privateprofile-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-localization-private-l1-1-0.dll"));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("GDI32.dll")));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("USER32.dll")));

    // checking user32 dependencies
    _ = try winsec.LoadLibraryW(L("win32u.dll"));
    _ = try winsec.LoadLibraryW(L("ntdll.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-localization-l1-2-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-registry-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-heap-l2-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-libraryloader-l1-2-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-eventing-provider-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-processthreads-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-synch-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-string-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-sysinfo-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-security-base-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-handle-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-errorhandling-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-string-l2-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-synch-l1-2-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-processenvironment-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-file-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-processthreads-l1-1-1.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-memory-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-profile-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-heap-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-memory-l1-1-3.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-privateprofile-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-atoms-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-heap-obsolete-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-string-obsolete-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-localization-obsolete-l1-2-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-stringansi-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-sidebyside-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-kernel32-private-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("KERNELBASE.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-kernel32-legacy-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-appinit-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-delayload-l1-1-1.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-delayload-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-apiquery-l1-1-0.dll"));

    // checking gdi32 dependencies
    _ = try winsec.LoadLibraryW(L("ntdll.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-heap-l2-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-libraryloader-l1-2-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-processthreads-l1-1-1.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-processthreads-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-profile-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-sysinfo-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-errorhandling-l1-1-0.dll"));
    try std.testing.expectError(error.OutOfVirtualMemory, winsec.LoadLibraryW(L("api-ms-win-gdi-internal-uap-l1-1-0.dll")));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-delayload-l1-1-1.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-delayload-l1-1-0.dll"));
    _ = try winsec.LoadLibraryW(L("api-ms-win-core-apiquery-l1-1-0.dll"));

    // SPDX-SnippetEnd
}