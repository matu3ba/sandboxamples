# Sandbox Examples

## Goals

1. Kernel- and user-space process based sandboxing examples for common hosted
   runtimes (Windows, Linux, MacOS, BSDs).
2. Each hosted runtime must contain assumptions and tests.
3. Portable abstractions are defered, but planned for later for a CI library
   with CI as use case.
4. Make code simple to cross-compile and natively compile.
5. Eventual goal is compare with (realtime) OS security model design to
   estimate how far off current OS implementations are and have some more
   structured designs to use for sel4 based OSes including drivers.
6. Tooling, good design and scalability: Library approach.

## Status

Windows
- [x] win32k mitigation + others
  - `test/win/main_win32k_mitigation.zig`
- [x] explicit handle inheritance
  - `test/win/main_explicit_handle_inheritance.zig`
- [x] job object system
  [link](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/) to limit
  memory, cpu usage and kill process group
    - use advanced api https://devblogs.microsoft.com/oldnewthing/20230209-00/?p=107812
    - use cases https://www.meziantou.net/killing-all-child-processes-when-the-parent-exits-job-object.htm
    - [x] basic
    - [x] `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION, SetInformationJobObject`
    - [x] Enumerate process names on system
    - `test/win/main_job_api.zig`
- [ ] file system sandboxing by user account (might need to remove and readd account)
      - ignore for now and always use explicit paths for PATH and alike.
      - use ntdll calls eventually, because we already have those in Zig libstd
      - NetUserAdd, NetUserGetInfo, and NetUserSetInfo; GetFileAttributesExW
      - GetNamedSecurityInfoW, SetNamedSecurityInfoW
      - AccessCheck, "Verifying Client Access with ACLs in C++"
      - GetFileAttributesExW
    - [ ] ACLs https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
    - [ ] fetch | execution time separation via different users
    - [ ] sample integrity checks on startups
    - [ ] access overview https://learn.microsoft.com/en-us/windows/security/identity-protection/access-control/access-control
    - reverse engineering problem source branch `fix_call_issues`
    - `test/win/main_ACL.zig`
    - `test/win/main_sec_info.c`
- [ ] impersonation (setuid under Windows) https://learn.microsoft.com/en-us/windows/win32/cossdk/client-impersonation-and-delegation
- [ ] network sandboxing (ie block specific user from internet access)
    - simple solution [not usable in Windows Home since it requires group policy](https://learn.microsoft.com/en-us/windows/win32/netmgmt/user-functions)
    - results indicate that [one would need to write your own firewall](https://stackoverflow.com/questions/2305375/blocking-all-windows-internet-access-from-a-win32-app)
      and run it in kernel mode
    - windows filtering platform (forgot what the API is called)
    - alternative: glasswire or portmaster
- [ ] user and system setup
- [ ] review for further accessible persistent state
- [ ] security shutdown
      - [regular shutdown only](https://learn.microsoft.com/en-us/windows/win32/shutdown/how-to-shut-down-the-system)
      - [shutdown reasons](https://learn.microsoft.com/en-us/windows/win32/shutdown/system-shutdown-reason-codes)
- [ ] idea: ETW based tracing + SCL via job unit
- [ ] idea: stub kernel32 and ntdll calls as admin to run own filter code in kernel space

Linux
- [ ] landlock (access control on kernel objects)
- [ ] seccomp-bpf (syscall filtering)
- [ ] parallel process spawn handle leak problem with workarounds
    - mutex or only standard handles
    - list of to be closed handles does not work, because order of handles
      which are inherited is not guaranteed to be stable and may vary during
      process lifetime
- [ ] file system sandboxing by user account (chown, chmod, Linux permission system)
- [ ] setuid
- [ ] cgroups (semantic mismatch, more powerful than job object),
    - https://www.schutzwerk.com/en/blog/linux-container-cgroups-03-memory-cpu-freezer-dev/
    - https://man7.org/linux/man-pages/man7/cgroups.7.html
    - not mitigating double fork: setrlimit (`RLIMIT_CPU` with SIGKILL or child process must handle it)
    - cgroups nice for upper process limit and network sandbox and
      solution to process tracking (double fork etc) with other being reaper approach
      - https://github.com/catern/supervise
- [ ] network sandboxing, seccomp-bpf
- [ ] what other persistent state may be accessible?
      - look into namespaces https://lwn.net/Articles/531114/
- [ ] minimal system setup, solution?
- [ ] tight system supervision setup, solution?
- [ ] security shutdown, lockdown?

MacOS
- [ ] sandbox-exec, look into firefox and chromium sandboxing code
      [stackoverflow question](https://stackoverflow.com/questions/56703697/how-to-sandbox-third-party-applications-when-sandbox-exec-is-deprecated-now)
      [some overview](https://www.karltarvas.com/macos-app-sandboxing-via-sandbox-exec.html)
- [ ] how to [wait for process group](https://jmmv.dev/2019/11/wait-for-process-group-darwin.html)
    - kevent NOTE\_TRACK needed
    - orphaned processes still not cleaned up
    - fork bomb unmitigated (applying posix limits needed)
    - workaround jobs not finishing in deadline: kill all processes with uid
- [ ] what other persistent state may be accessible?
- [ ] minimal system setup, solution?
- [ ] tight system supervision setup, solution?
- [ ] security shutdown, solution?

Other BSDs and Unixes
- [ ] Kernel API sandboxing works likely very similar to other solutions
- [ ] process API with identical problems
- [ ] network parts unclear
- [ ] other parts are highly configuration dependent

## Tests and implementation

Tests are to be found in test/.

General procedure:
- 1. Find reasonable short example code
- 2. Add testfile.c to test\win\ and build.zig
- 3. zig translate-c test\win\testfile.c > test\win\testfile.zig, add it to build.zig
- 4. simplify test\win\testfile.zig, implementation, error abstractions

Deviation:
- Follow different example code, ideally with sufficient explanations
- Opaque pointers (Windows) hard to debug/check for correctness of operations
- More than 3 parameter with optional pointer or weird problems
- Standalone C and Zig files as libs, main calls C version and vice versa
  * bare bone C pointers in Zig
  * identical logic for Zig and C version
  * combinations to figure out what went wrong
  * view assembly diffs
  * record program and inspect fn args structures
- TODO setup Kernel debugging to get logic
- TODO program + procederes to extract underlying in-Kernel structures/code
  collection instead of opaque pointers (ntdll trace, ghidra?)
- TODO trace fn args structures => debugger plugin

## References
