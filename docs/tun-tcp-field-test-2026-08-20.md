# TUN TCP Field Test: 2026-08-20

## Scope

Commit `5c4f4da` from `research/tun-full-integration` was built as a static
`aarch64-linux-musl` ReleaseFast ELF for `cortex_a53` and tested on the active
GL.iNet GL-MT6000 through SSH. The tested TCP engine is commit `023121a`.
The binary SHA-256 was
`433b8ace604b6b2665da782e8446682029d538aca91c258a212c0e8301679c1b`.

The test used a separate process, config, `xztcp0` interface, and four
destination-specific routes. It did not change firewall or boot state and did
not exercise UDP. An already-running SOCKS instance was left untouched. All
test processes, routes, interface state, and remote files were removed after
the run.

HTTPS payloads came from `speed.cloudflare.com` through the existing
VLESS/REALITY/Vision outbound. A direct 16 by 8 MiB control run completed all
streams in 1.81 seconds, so the endpoint and WAN path could sustain the
concurrency used by the failing TUN cases.

## Results

| Runtime capacity | Workload | Result | Sampler elapsed | Process CPU | Peak RSS | Peak threads | Peak FDs |
|---|---|---:|---:|---:|---:|---:|---:|
| default 64 workers | IPv4 smoke, 64 KiB | pass | 0.64 s wall | - | - | - | - |
| default 64 workers | IPv6 smoke, 64 KiB | pass | 0.65 s wall | - | - | - | - |
| default 64 workers | IPv4, 1 by 64 MiB | 1/1 | 15 s | 2.34 s | 4,044 KiB | 8 | 8 |
| default 64 workers | IPv4, 8 by 8 MiB | 8/8 | 3 s | 2.07 s | 25,436 KiB | 65 | 29 |
| default 64 workers | IPv6, 8 by 4 MiB | 8/8 | 7 s | 2.03 s | 26,208 KiB | 65 | 29 |
| default 64 workers | 40 short IPv4 connections | 40/40 | 5 s | 0.69 s | 34,156 KiB | 65 | 41 |
| default 64 workers | IPv4, 16 by 8 MiB | 12/16 | 181 s | 4.49 s | 23,416 KiB | 65 | 41 |
| 128 workers | IPv4, 16 by 8 MiB | 16/16 | 8 s | 6.03 s | 29,468 KiB | 83 | 53 |
| 128 workers | IPv4, 24 by 4 MiB | 24/24 | 7 s | 4.72 s | 47,320 KiB | 123 | 77 |
| 128 workers | IPv4, 32 by 2 MiB | 24/32 | 21 s | 2.68 s | 53,516 KiB | 129 | 74 |
| 192 workers | IPv4, 32 by 2 MiB | 32/32 | 5 s | 3.69 s | 56,728 KiB | 163 | 101 |

Every completed workload returned to the baseline five file descriptors. The
TUN process remained alive after failed cases and all flow FDs were released.
IPv4 and IPv6 both established VLESS/REALITY/Vision sessions; IPv6 reached
Vision raw handoff.

## Capacity finding

The failures follow the executor ceiling rather than payload size or the
remote endpoint. The default 70 MiB capacity calculation selects 64 workers.
The 16-stream failure peaked at 65 process threads. With 128 workers, 16 and 24
streams passed, while 32 streams failed at 129 threads. With 192 workers the
same 32-stream workload passed and peaked at 163 threads. Failed runs logged
`ConcurrencyUnavailable`, canceled REALITY initialization, client TLS EOF, or
client timeout.

The current TUN integration schedules roughly five concurrent executor tasks
per active proxied flow: the flow owner, retransmission pump, dispatcher, and
bridge pumps. `maxConnections` therefore does not currently protect the shared
worker pool. Raising the worker and memory budgets hides the problem on this
1 GiB router, but it is not the preferred production fix. The integration
should reduce per-flow task consumption or add admission/backpressure derived
from the effective runtime worker capacity.

## Retransmission coverage

The deterministic TCP state tests cover RTO/backoff, cumulative and partial
ACKs, duplicate ACK fast retransmit, and retry exhaustion. Live HTTPS exercised
the timer-enabled engine but did not deliberately drop packets. The router had
no `tc`/netem binary or netem module. No package installation or temporary
firewall drop rule was used, so a controlled live-loss test remains pending.

## Worker refactor follow-up

Commit `c167f08` replaced every per-flow retransmission task with one shared
TUN timer and folded the uplink pump into the flow owner. It also made runtime
capacity derive from the process memory budget. The default 512 MiB setting
selected 468 workers and 2,340 lazy raw-connection slots. The tested AArch64
binary SHA-256 was
`d2a34a3921e2ee953d44855486deb4421aca197feef7b5d031408cf1a7e920e0`.

At idle the configured 468-worker process had only four threads and 1,868 KiB
RSS, confirming that capacity does not preallocate workers or resident stacks.
After IPv4 and IPv6 smoke tests it had nine threads and 4,244 KiB RSS.

| Workload | Result | Sampler elapsed | Process CPU | Peak RSS | Peak threads | Peak FDs |
|---|---:|---:|---:|---:|---:|---:|
| IPv4, 32 by 2 MiB | 32/32 | 5 s | 3.49 s | 39,716 KiB | 100 | 98 |
| IPv4, 64 by 1 MiB | 64/64 | 5 s | 4.28 s | 82,188 KiB | 196 | 194 |
| IPv4, 128 by 512 KiB | 127/128 | 17 s | 5.57 s | 161,304 KiB | 388 | 329 |

The comparable pre-refactor successful 32-flow run needed 163 threads and
56,728 KiB RSS. The refactor reduced threads by 38.7% and peak RSS by 30.0%
without increasing the five-second sampler interval. No run logged
`ConcurrencyUnavailable`, and every run returned to five FDs.

The single 128-flow TUN failure was not a worker-capacity failure. A direct
128-flow control run against the same endpoint failed three TLS connections;
the TUN run failed one. A later 96-flow TUN run and its direct control each
failed one endpoint TLS connection. The TUN process logged two REALITY
initialization timeouts across the high-concurrency sequence but remained
healthy.

Zig `Io.Threaded` does not retire workers. After the largest burst, the idle
process retained 388 threads, 168,164 KiB RSS, and 501,544 KiB virtual size,
while FDs returned to five. The 1 MiB stack is demand-paged rather than charged
fully to RSS, but touched pages stay resident until process exit. Reducing
per-flow tasks therefore saves real memory without reintroducing the TLS stack
overflow risk of smaller worker stacks.
