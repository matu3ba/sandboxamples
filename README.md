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
- [ ] win32k mitigation
- [ ] explicit handle inheritance
- [ ] permission limitations of process and subprocess (user based?)
    - Applications must set security limits individually for each process.
    - Permissions also organized into user groups instead of bits
- [ ] job object system
  [link](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/) to limit
  memory, cpu usage and kill process group
- [ ] file system sandboxing by user account (might need to remove and readd account)
      [link](https://learn.microsoft.com/en-us/windows/win32/api/lmaccess/ns-lmaccess-user_info_1008)
    - use ACLs + integrity check on startup
- [ ] network sandboxing?
    - simple solution [not usable in Windows Home since it requires group policy](https://learn.microsoft.com/en-us/windows/win32/netmgmt/user-functions)
    - results indicate that [one would need to write your own firewall](https://stackoverflow.com/questions/2305375/blocking-all-windows-internet-access-from-a-win32-app)
      and run it in kernel mode
    - windows filtering platform (forgot what the API is called)
    - alternative: glasswire or portmaster
- [ ] what other persistent state may be accessible?
- [ ] minimal system setup, solution?
- [ ] tight system supervision setup, solution?
- [ ] security shutdown, solution?

Linux
- [ ] seccomp
- [ ] parallel process spawn handle leak problem with workarounds
    - mutex
    - provide list and do all the close work in child process before execve via
      another buffer only to validate kernel handle to semantics plus logic on
      top, which sounds like what Windows is doing inside Kernel
- [ ] setuid, lockdown?
- [ ] cgroups (semantic mismatch, more powerful than job object), less useful: setrlimit
    - cgroups nice for upper process limit and network sandbox and only
      solution to process tracking (double fork etc)
- [ ] file system sandboxing by user account
- [ ] network sandboxing, seccomp
- [ ] what other persistent state may be accessible?
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
    - fork bomb unmitigated
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

## Less hacky kernel design and usage

Let a process be a group of (one or more) execution contexts (usually refered to as threads)
with identical security domain for inter and user-space accessible kernel
structures.
Processes with security domain form relations to other processes affecting
the overall schedule of execution contexts (statically, predefined dynamically
or freely with relational dependencies).
Interprocess communication can buffered with some fixed (SIGTERM) or
dynamically limited size (queue) and processed immediately (SIGKILL) or defered
on scheduling (SIGTERM, realtime signals) in process automatically (SIGTERM) or
via polling by the process (realtime signals, queue, socket, etc).

TODO Make formal model for (soft) realtime secure OS design space in
MODEL.md and scheduling tradeoffs regular OSes make and how it affects the
overall system.
It also describes security domains and scheduling choices, which can be
made to ensure deadline of the overall systems can be ensured (under assumption
that the upper time bound of Kernel time can be ensured).
Note, that the ideal model separates security domains from scheduling with
process tracking and that buffers have their own security domains with
permissions from multiple processes (ie for signaling) and being predefined
reattachable to take into account scheduling deadlines.

An optimal schedule for execution contexts and processes would make the
scheduler aware of the conditions and dependencies to other execution contexts
and processes, but this makes proving correctness of the scheduler hard.
Likewise, an optimal security system would ensure all attack surface could be
ruled out, but this makes designing the system at kernel level and user level
or (for sufficiently simple systems) proving correctness hard.

## Tests and implementation

To be filled with implementation structure and implementation list.

## References
