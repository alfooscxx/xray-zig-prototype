# Real-Server Performance

## 2026-07-23 Runtime CPU And Lifetime Audit

The raw bridge previously rebuilt its poll set every 20 ms, including while it
had no connections. A three-second idle `strace -f -c` sample completed 146
`poll` calls. The reactor now blocks on an `eventfd`-backed poll set, wakes
immediately when producers publish a connection, and performs only a one-second
bounded poll to observe cooperative runtime cancellation. The same sample
completed 2 `poll` calls, a 98.6% reduction in idle polling. Connection
publication uses a lock-free atomic handoff stack; the previous hand-written
spin lock was removed.

The reactor now also closes both active and queued connections when it stops.
A local ReleaseFast SOCKS/freedom churn test, which exercises the raw handoff on
every request, produced this settled state:

| Completed connections | RSS | FDs | Threads |
|---:|---:|---:|---:|
| 100 | 2,024 KiB | 5 | 4 |
| 600 | 2,024 KiB | 5 | 4 |
| 1,100 | 2,024 KiB | 5 | 4 |

A separate 512-request run at concurrency 64 completed without failures and
returned to 5 FDs. It retained 56 on-demand I/O workers and 15.8 MiB RSS; these
workers are intentionally kept by `Io.Threaded`, so sizing under burst traffic
must distinguish that bounded pool from per-connection reactor retention.

FakeDNS cache hits now normalize names in a stack buffer and allocate only on a
new mapping. Allocation-failure tests cover every insertion allocation and
verify complete cleanup. On Linux, resolver-backed DNS uses an `AF_UNIX`
`socketpair` for its internal dispatcher stream instead of creating a temporary
TCP listener for every query. The outbound-routed concurrent DNS e2e suite and
the real-Xray REALITY/Vision traffic suite pass with these changes.

This audit did not find another busy-wait loop. Remaining blocking locks are
`Io.Mutex` instances for FakeDNS maps and the shared startup log writer, and
bounded `Io.Semaphore` instances for DNS queries and REALITY handshakes. These
sleep through the runtime rather than spinning. Under sustained REALITY traffic,
the negotiated cipher remains the dominant CPU cost; use the explicit
`chacha20-only` policy on software-AES targets as described below.

## 2026-07-22 Baseline

The benchmark used the field REALITY/Vision server from `field-config-test.json`, HTTPS payloads from Cloudflare's speed endpoint, and fresh SOCKS connections for latency samples. The Zig client was built with Zig 0.16.0 and `-Doptimize=ReleaseFast`. The comparison client was the official Xray 26.3.27 Linux x86-64 binary.

CPU usage was read from Linux process user and system CPU jiffies around each workload. `cpu_ms_per_MiB` is the most useful comparison because wall-clock CPU percentage changes with network throughput.

| Workload | Client | Throughput | CPU load | CPU ms/MiB | Peak RSS |
|---|---|---:|---:|---:|---:|
| Single 32 MiB HTTPS stream | Zig ReleaseFast | 7.676 MiB/s | 3.60% | 4.688 | 2.93 MiB |
| Single 32 MiB HTTPS stream | Xray 26.3.27 | 8.406 MiB/s | 12.35% | 14.688 | 34.16 MiB |
| Four concurrent 8 MiB streams | Zig ReleaseFast | 8.054 MiB/s | 4.78% | 5.938 | 6.34 MiB |
| Four concurrent 8 MiB streams | Xray 26.3.27 | 8.168 MiB/s | 11.23% | 13.750 | 34.15 MiB |

Ten fresh `https://example.com/` requests completed without failures for both clients:

| Client | Mean | p50 | p90 | Proxy CPU load | Peak RSS |
|---|---:|---:|---:|---:|---:|
| Zig ReleaseFast | 0.748 s | 0.742 s | 0.818 s | 0.53% | 3.32 MiB |
| Xray 26.3.27 | 0.549 s | 0.549 s | 0.565 s | 0.72% | 32.33 MiB |

The payload tests are network-bound on this host. At the measured rate, Zig used 2.3 to 3.1 times less CPU per transferred byte than Xray. This relative result is useful for router selection, but absolute CPU percentages cannot be transferred directly to a different CPU architecture or clock speed.

The Zig ReleaseFast executable was 8.1 MiB; the stripped Xray executable was 35 MiB.

## Reproduction

Build and verify an optimized client from `xray-zig/`:

```sh
zig build test -Doptimize=ReleaseFast
zig build -Doptimize=ReleaseFast
```

Wrap the field config's `proxy` outbound in a local SOCKS inbound, remove routing exceptions so every benchmark destination uses `proxy`, and run identical HTTPS requests through each client. Use process CPU time around the transfer rather than sampling `%CPU` from `top`.

The default Zig build mode is Debug and is not representative of router performance.

## 2026-07-22 MIPS32 Field Result

The test target is big-endian MIPS32r2 O32 soft-float with 154 MiB RAM. Go Xray and the Zig client ran side-by-side, with Zig on a temporary SOCKS inbound. Both clients used the same remote REALITY/Vision server.

An 8 MiB byte range from `cdn.kernel.org` produced this same-origin comparison:

| Client | Throughput | Process CPU | CPU s/MiB | Peak RSS |
|---|---:|---:|---:|---:|
| Zig ReleaseFast, Firefox/AES policy | 0.582 MiB/s | 12.86 s | 1.61 | 3.48 MiB |
| Existing Go Xray | 1.654 MiB/s | 5.20 s | 0.65 | about 46 MiB idle RSS |

The Vision framing fix reduced Zig's CPU cost from the earlier 2.23 CPU s/MiB result to 1.61 CPU s/MiB when the server kept the response inside outer TLS. A separate Cloudflare trace entered direct copy in both directions, but the kernel.org workload did not: aggregate instrumentation observed 8.41 MiB framed and zero downlink direct bytes. Xray's server-side direct-copy transition is therefore origin- and read-boundary-dependent.

The final isolated build returned HTTP 200 through the real server for `example.com`, `cloudflare.com`, and jsDelivr. A final 4 MiB CDN range completed at 0.568 MiB/s.

## MIPS Cipher Mitigation

Isolation showed that the generic Zig bridge is not expensive. A `freedom` sidecar transferred the same 8 MiB at 3.05 MiB/s using 0.26 CPU-seconds (0.033 CPU s/MiB). Rate-limiting it to 0.6 MiB/s used 0.15 CPU-seconds, ruling out scheduler wait overhead. The slow REALITY session negotiated `AES_128_GCM_SHA256`, whose portable Zig implementation has no acceleration on this MIPS32 CPU.

The new explicit `realitySettings.cipherPolicy: "chacha20-only"` advertises TLS 1.3 and TLS 1.2 ChaCha20 suites but excludes AES. The real field server negotiated `CHACHA20_POLY1305_SHA256`. The clean stripped MIPS build produced:

| Client | Throughput | Process CPU | CPU s/MiB | Peak RSS |
|---|---:|---:|---:|---:|
| Zig ReleaseFast, ChaCha20-only | 3.343 MiB/s | 1.36 s | 0.17 | 3.46 MiB |
| Zig ReleaseFast, Firefox/AES policy | 0.582 MiB/s | 12.86 s | 1.61 | 3.48 MiB |
| Existing Go Xray | 1.654 MiB/s | 5.20 s | 0.65 | about 46 MiB idle RSS |

On this workload, ChaCha20 reduced Zig CPU time per byte by about 89% versus AES-GCM and by about 74% versus the existing Go Xray. The throughput result is network-sensitive, but process CPU jiffies and transferred byte counts are direct measurements.

The same clean build was also tested with four concurrent 4 MiB ranges:

| Client | Aggregate throughput | Process CPU | CPU s/MiB | Observed RSS |
|---|---:|---:|---:|---:|
| Zig ReleaseFast, ChaCha20-only | 5.337 MiB/s | 4.61 s | 0.288 | 6.02 MiB |
| Existing Go Xray | 3.155 MiB/s | 12.95 s | 0.809 | 35.03 MiB |

Zig consumed about 154% of one CPU over the 3.00 s concurrent run, compared with about 255% for Go over 5.07 s. This directly addresses the router's high-traffic failure mode: the ChaCha20 build moved more traffic while using substantially less total CPU and memory.

The tradeoff is fingerprint fidelity: removing AES suites no longer produces Firefox's normal cipher-suite list. The default remains `cipherPolicy: "firefox"`; the MIPS field fixture opts into `"chacha20-only"` explicitly.

## Concurrency Fix

A mixed transparent-routing workload exposed a runtime limit that the isolated throughput tests did not: Zig 0.16's default `Io.Threaded` pool created permanent workers with 16 MiB virtual stacks. The test reached 80 threads, 1.3 GiB virtual size, and 23.4 MiB RSS; new accepts then stalled. An initial 256 KiB stack experiment was too small for the MIPS TLS/crypto call path and exited under four streams.

The next mixed-traffic test reached the 64-worker ceiling within one minute. Each live transparent connection used one handler/downlink worker and one uplink worker, so the old limit admitted only about 30 simultaneous connections. About 65 established sessions were observed, requiring more than 130 workers before allowing for bursts.

The bridge now polls both sockets and drains both directions from one connection worker. The runtime uses 1 MiB stacks and later moved from this initial 96-worker revision to a 128-worker limit with listener backpressure. Workers are created on demand. Both 256 KiB and 512 KiB stacks are unsupported: 256 KiB exited under earlier four-stream MIPS TLS load, while 512 KiB left downlink workers corrupted and stalled during a 16-stream field test.

The 1 MiB/64-worker revision produced:

| Isolated workload | Throughput | Process CPU | CPU s/MiB | RSS after test | Threads | Virtual size |
|---|---:|---:|---:|---:|---:|---:|
| Four concurrent 4 MiB SOCKS ranges | 5.702 MiB/s | not sampled | not sampled | 6.53 MiB | 13 | 18.3 MiB |
| Four concurrent 4 MiB transparent ranges, workstation-only rule | 5.895 MiB/s | not sampled | not sampled | 8.07 MiB | 16 | 22.0 MiB |
| Sixteen concurrent 1 MiB SOCKS ranges | 2.414 MiB/s | 7.98 s | 0.499 | 15.49 MiB | 37 | 48.45 MiB |

The workstation-only transparent rules were removed after testing.

## Interactive Traffic Regression

A later mixed-traffic test showed that fixed-address HTTPS probes were insufficient: general interactive traffic stopped, including existing WebSocket sessions. The one-worker Vision uplink assembled a partial inner TLS record by synchronously reading until the full declared record length was present. While blocked there, the same worker could not service downstream data.

The uplink is now an incremental state machine. It reads one available fragment, preserves `pending_len`, and returns to the bidirectional poll loop until the record is complete. A later `readAvailable` fix also prevents an already-buffered client request from triggering a second blocking socket read before the bridge can service downlink traffic.

The corrected binary was staged beside Go Xray without changing PREROUTING and tested through the real field REALITY/Vision server:

| Workload | Result |
|---|---:|
| `example.com`, Cloudflare, and jsDelivr HTTPS | 3/3 HTTP 200 |
| 32 concurrent 256 KiB kernel CDN ranges | 32/32, 8 MiB in 5 s |
| One fragmented WSS session | 500/500 round trips in 80.6 s |
| Eight fragmented WSS sessions | 800/800 round trips in 18 s |
| Sixteen fragmented WSS sessions | 1600/1600 round trips in 19 s |

The WSS harness used a TLS WebSocket echo endpoint reached through an Xray server. After the ClientHello, the client split every encrypted write into 7-byte chunks with 1 ms spacing. The endpoint confirmed every successful HTTP upgrade and frame count. One earlier uninstrumented eight-client batch completed seven clients and timed out one upgrade; that timeout did not reproduce across the following 24 instrumented clients and remains a residual field-test risk.

After the CDN burst, the Zig worker pool retained 37 threads at 19.6 MiB RSS and 49.6 MiB virtual size.

### Empty-Preface Response Deadlock

A later workstation reproduction found a second interactive-traffic failure that
was independent of router CPU and memory. When the 500 ms initial payload wait
expired, Zig sent an empty Vision camouflage frame and then blocked reading the
VLESS response before starting client upload. Delayed client bytes could never
reach the server. Official Go Xray uploads requests concurrently with its
response wait and did not fail.

The fixed response wait polls both sockets, forwards delayed client bytes, and
parses the VLESS response incrementally from the same connection worker. Three
fresh ReleaseFast Zig processes passed 80/80 clients and 1600/1600 WSS frames in
8.55, 7.92, and 7.13 seconds. The matched Go control passed 80/80 in 5.35
seconds. `docs/vision-response-deadlock.md` preserves the complete symptoms,
syscall/trace evidence, deterministic reproduction, root cause, and fix.

The initial 96-worker bound was a separate failure: a 128-client burst admitted
94/128 Zig clients while Go admitted 128/128. TCP inbounds now queue at worker
capacity instead of closing accepted sockets, and the cap is 128 workers. A
32-session VLESS/REALITY setup semaphore also prevents simultaneous ClientHello
bursts from leaving upstream TCP payload unacknowledged. Three final immediate
128-client runs passed 128/128; peak x86 RSS was 70.2 MiB at 129 threads. See
`docs/vision-response-deadlock.md` for the complete evidence and matched CPU
results.

## 2026-07-23 Expanded MIPS32 Validation

The expanded field test ran Zig on a SOCKS inbound through a real Xray server. CPU values are process user plus system jiffies; RSS and FD values are sampled peaks. Both proxy processes were effectively idle outside each workload.

The mixed HTTPS matrix used 8 requests each to IANA, Cloudflare, kernel.org/Fastly, and jsDelivr at concurrency 16:

| Client | Result | Wall time | Process CPU | Peak RSS | Peak FDs |
|---|---:|---:|---:|---:|---:|
| Zig trace, staged SOCKS | 32/32 | 5.37 s | 13.62 s | 23.89 MiB | 39 |
| Go Xray, transparent | 32/32 | 3.61 s | 7.79 s | 35.86 MiB | 224 |

This handshake-heavy workload favors Go for both latency and CPU. It should not be used as the high-throughput CPU estimate.

Four concurrent 8 MiB Cloudflare speed transfers produced the opposite result:

| Client | Result | Throughput | Process CPU | CPU s/MiB | Peak RSS | Peak FDs |
|---|---:|---:|---:|---:|---:|---:|
| Zig trace, staged SOCKS | 32 MiB | 5.508 MiB/s | 7.36 s | 0.230 | 20.85 MiB | 15 |
| Go Xray, transparent | 32 MiB | 3.671 MiB/s | 17.36 s | 0.543 | 35.08 MiB | 158 |

Zig used about 58% less process CPU per transferred byte and completed about 50% faster in this run. This is the more relevant result for a router that saturates under sustained proxy traffic.

A dependency-free WSS harness split every encrypted client TLS write into 7-byte TCP writes with 1 ms spacing. Each session validated the HTTP upgrade, binary echoes, and periodic ping/pong:

| Client | Result | Wall time | Process CPU | Peak RSS | Peak FDs |
|---|---:|---:|---:|---:|---:|
| Zig trace, staged SOCKS | 16/16 clients, 1600/1600 frames | 20.34 s | 7.47 s | 21.57 MiB | 39 |
| Go Xray, exact temporary transparent rule | 16/16 clients, 1600/1600 frames | 11.61 s | 14.89 s | 34.87 MiB | 196 |

Go completed the fragmented WSS batch faster but used about twice the process CPU. Zig also completed one 500-frame fragmented session in 89.27 seconds without a timeout.

Routing and FakeDNS field checks passed:

- A `.ru` SOCKS request created no VLESS session, while an unmatched request created one.
- A SOCKS request to `192.168.1.1` reached the router through the private-CIDR direct rule.
- FakeDNS returned stable `198.18.0.0/15` A and `fc00::/18` AAAA mappings.
- A temporary workstation-only rule sent `198.18.0.1:443` to staged redirect port `22345`; reverse mapping recovered `example.com` and completed HTTPS through REALITY. The exact rule was then removed.

## Pre-Deadlock-Fix Validation

Reduced acceptance on this exact binary passed:

- Mixed HTTPS: 16/16 in 3.38 seconds.
- Four concurrent 4 MiB transfers: 16 MiB at 5.275 MiB/s.
- Fragmented WSS: 8/8 clients and 400/400 frames in 9.54 seconds.
- Domain-direct, private-IP direct, and FakeDNS A/AAAA probes.

Across the reduced HTTPS plus transfer sample, peak RSS was 7.35 MiB, peak threads 14, and peak FDs 23. This confirms trace logging and its retained worker activity materially inflate memory measurements; sizing should use the non-trace ReleaseFast binary.

Reproduce the field workloads from the workstation:

```sh
XRAY_ZIG_SOCKS_PROXY=socks5h://192.168.1.1:21080 tests/field/http-matrix.sh
XRAY_ZIG_SOCKS_PROXY=socks5h://192.168.1.1:21080 tests/field/sustained-transfer.sh
python3 tests/field/fragmented-wss.py --target-host VPS_IP --server-name VPS_IP.nip.io
```

`tests/field/router-sample.sh` provides `start`, `summary`, and `stop` sampling
commands. Temporary WSS sidecars and diagnostic NAT rules must be stopped or
removed after each field run.
