# Raw-Reactor Memory Leak

## Failure Symptoms

Under sustained connection churn, a supervised process exited with status 137:

```text
Thu Jul 23 16:49:01 MSK 2026 xray-zig exited status=137
```

Status 137 is `SIGKILL`. The exact sender was not captured, but system memory
pressure and the reproducible leak below make OOM termination the supported
diagnosis.

## Reproduction

Every Vision connection that reaches raw handoff is adopted by
`src/net/reactor.zig`. Closing such a connection calls `allocator.destroy`, so
the defect can be reproduced by repeatedly opening an HTTPS connection through
Vision, allowing raw handoff, and closing it.

The fixed trace build was checked against the real Xray server with 408
confirmed `raw handoff` events. After a 32-connection warm-up, successive RSS
checkpoints were:

| Completed raw handoffs | RSS |
|---:|---:|
| 32 | 4.9 MiB |
| 154 | 7.0 MiB |
| 282 | 7.0 MiB |
| 408 | 7.6 MiB |

This is a plateau rather than growth proportional to completed connections.

## Root Cause

`main.zig` passed `init.arena.allocator()` into `core.Runtime`. The runtime then
passed that allocator to the raw reactor. Each reactor `Connection` contains
two 16 KiB buffers plus socket and state fields. Arena `destroy` is a no-op, so
completed raw-handoff connections permanently retained their allocation until
process exit.

At hundreds of completed sessions, retained reactor objects consumed tens of
MiB in addition to worker stacks, TLS state, and socket memory.

## Fix

Configuration and CLI data remain in the process-lifetime arena. Runtime-owned
objects were first moved to `init.gpa`, Zig's thread-safe general-purpose
allocator. The reactor now has a separate allocator and uses
`std.heap.page_allocator`: in ReleaseFast, `init.gpa` is the SMP allocator and
may cache freed pages. Reactor `destroy` now unmaps each large connection
allocation when the raw bridge closes, returning it to the kernel promptly.
FakeDNS and the threaded I/O runtime remain on `init.gpa`; using a page
allocator for their smaller allocations would add unnecessary mappings and
system calls.

## Validation

- `zig build test -Doptimize=ReleaseFast` passed.
- The real-Xray REALITY/Vision traffic harness passed.
- The 408-handoff real-server churn run plateaued at 7.6 MiB RSS.
- A later local ReleaseFast SOCKS/freedom run plateaued at 2,024 KiB RSS,
  5 FDs, and 4 threads at 100, 600, and 1,100 completed raw handoffs.
- Reactor shutdown now explicitly closes active and pending handoffs. A
  512-request, 64-way contention run completed without failures and returned
  to 5 FDs.
