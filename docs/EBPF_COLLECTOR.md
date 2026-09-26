# eBPF Collector Design

The MVP is eBPF-capable by architecture, but does not ship privileged kernel code. This keeps the repository safe to run anywhere while defining the interface needed for a Linux collector.

## Candidate Kernel Signals

Useful defensive probes include:

- `sched_process_exec` for process starts
- `sched_process_exit` for process exits
- LSM hooks for file open/write decisions where available
- tracepoints or kprobes for TCP connect events
- optional cgroup or namespace metadata for container workloads

## User-Space Responsibilities

The eBPF program should keep kernel work minimal:

- capture stable identifiers and timestamps
- submit compact events through a ring buffer
- avoid parsing large strings or applying complex policy in kernel space

The user-space adapter should:

- enrich process IDs with command line and parent context
- map raw observations to `Event`
- assign causal parents from process ancestry and resource lineage
- send events to `ChainWriter`

## Safety Rules

- do not block syscalls in the MVP collector
- do not collect file contents
- do not collect secrets or keystrokes
- prefer hashes, paths, PIDs, UIDs, cgroups, and socket metadata
- document every captured field

## Example Mapping

```text
sched_process_exec
  pid=1510 ppid=1442 comm=bash

Event(
  event_type="process_start",
  subject="proc:sshd:1442",
  object="proc:bash:1510",
  parents=("evt:parent-process",),
  data={"pid":1510,"ppid":1442,"comm":"bash"}
)
```
