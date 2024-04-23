// Open source Windows syscall api monitoring tools would be based on ETW and
// some logic to decide what to do on a possible security breach like emergency
// shutdown with the evidence somehow stored securely and securely accessible
// by followup start for inspection.
// Some metric could be user-specified whitelist of win32k and ntdll system calls
// from https://github.com/j00ru/windows-syscalls.
//
// Manual monitoring of processes like https://github.com/microsoft/Detours
// does not take into account, that the process could not cooperate.
