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

