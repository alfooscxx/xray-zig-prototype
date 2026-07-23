# Vision Response-Wait Deadlock

## Failure Symptoms

During a mixed transparent-routing test, direct-routing exceptions continued to work while
proxied HTTPS and WebSocket traffic first reported TLS failures and then timed
out. The Zig process remained alive, the proxy server accepted new REALITY
sessions, and the host showed neither a crash nor OOM-killer evidence.

The same failure reproduced on the x86 workstation through the real VPS Xray
server. Fresh Zig processes failed nondeterministically near the concurrency
boundary, including 36/80 and 60/80 completed clients. Official Go Xray passed
the same workload. A stalled 80-client Zig run showed:

- 80 `reality-ready` trace events.
- 80 `initial-ready` trace events.
- 60 `response-ready` and raw-handoff events.
- 20 workers blocked in `readv()` on their REALITY sockets.
- The same 20 connections had sent an empty initial Vision padding frame.

## Deterministic Reproduction

`fragmented-wss.py` has a `--post-connect-delay` option that delays the inner
TLS ClientHello after SOCKS CONNECT succeeds. A delay above the 500 ms initial
preface timeout forces the affected path without requiring high concurrency:

```sh
./zig-out/bin/xray-zig run -config /tmp/xray-zig-x86-load.json

python3 tests/field/fragmented-wss.py \
  --proxy-host 127.0.0.1 --proxy-port 21081 \
  --target-host VPS_IP --server-name VPS_IP.nip.io \
  --clients 1 --frames 20 --fragment-size 7 --fragment-delay 1 \
  --post-connect-delay 750 --timeout 15
```

Before the fix, the client timed out waiting for the proxied TLS handshake.
After the fix, the trace shows an empty initial frame, one or more
`response-wait uplink` events, and then `response-ready`.

The original probabilistic load reproduction omits `--post-connect-delay` and
uses `--clients 80`.

## Root Cause

The Zig VLESS outbound serialized three phases:

1. Send the VLESS request and one initial Vision frame.
2. Block until the VLESS response header arrives.
3. Start the bidirectional Vision bridge.

When no client payload arrived within 500 ms, phase 1 sent an empty
`CommandPaddingContinue` frame. Later client bytes could not be uploaded because
the bridge had not started, while the server did not produce the response needed
to advance the Zig client. The connection deadlocked at the VLESS response
header.

Go Xray does not serialize these phases. Its request upload continues while its
response path waits for the VLESS response, so a delayed ClientHello still
reaches the server.

## Fix

`src/proxy/vless/outbound.zig` now uses a single-worker poll loop while waiting
for the VLESS response header. The loop:

- forwards newly readable client bytes through the existing Vision encoder;
- flushes the outer REALITY/TLS writer;
- incrementally reads and validates the VLESS response header; and
- enters the normal bidirectional bridge once that header is complete.

This preserves the one-worker-per-connection memory model and does not add a
temporary upload thread. Worker-capacity changes described below are separate
from this protocol fix.

## Validation

On 2026-07-23, through the real VPS Xray server and WSS sidecar:

| Client | Workload | Result | Wall time |
|---|---|---:|---:|
| Zig before fix | 80 clients, 20 frames | 60/80 | 61.18 s timeout window |
| Zig after fix, fresh run 1 | 80 clients, 20 frames | 80/80 | 8.55 s |
| Zig after fix, fresh run 2 | 80 clients, 20 frames | 80/80 | 7.92 s |
| Zig after fix, fresh run 3 | 80 clients, 20 frames | 80/80 | 7.13 s |
| Go Xray control | 80 clients, 20 frames | 80/80 | 5.35 s |
| Zig delayed-preface regression | 1 client, 20 frames | 1/1 | 3.52 s |

The fixed code also passed the local real-Xray REALITY harness for normal and
Vision traffic.

## Worker Admission

The old 96-worker runtime immediately closed accepted sockets when
`Io.Group.concurrent` returned `ConcurrencyUnavailable`. An initial 128-client
burst therefore admitted 94 clients and reset 34. This was not the
response-wait deadlock: rejected clients failed immediately instead of reaching
`initial-ready` and timing out.

TCP inbounds now retain one accepted socket and retry scheduling every 10 ms
while the pool is full. Remaining connections stay in the kernel listen backlog.
The runtime cap is 128 workers, which allows about 124 established
connections after the reactor and inbound workers; later bursts queue rather
than reset. Capacity waits are visible at warning level.

## Handshake Burst

After admission was fixed, an immediate 128-client launch exposed a separate
pre-REALITY timeout. A representative run completed 125/128. The three failed
connections never emitted `reality-ready`:

- client sockets were `CLOSE-WAIT` with 518 queued ClientHello bytes;
- upstream sockets were `ESTABLISHED` with 517 bytes in `Send-Q`;
- Linux reported one unacknowledged segment, eight retransmissions, and a
  120-second retransmission timeout; and
- the VPS path had acknowledged the TCP handshake but none of the REALITY
  ClientHello payload.

Adding a 10 ms client launch delay produced 128/128, identifying the trigger as
the simultaneous outbound handshake burst. VLESS setup now uses a 32-permit
semaphore around TCP connect plus REALITY initialization. The permit is released
before the long-lived Vision bridge, so established connection capacity remains
128 workers while CPU-heavy crypto and ClientHello bursts are bounded.

Three immediate 128-client runs then completed 128/128, with the two stable
fresh-process runs taking 6.55 and 6.38 seconds. The first measured run reached
70.2 MiB peak RSS at 129 process threads on x86.

## Resource Comparison

Measurements on a 154 MiB MIPS32 target showed that an isolated Zig allowance
near 80 MiB accommodates the 128-worker stress test.

Matched x86 CPU deltas through the real server were:

| Workload | Zig CPU | Go CPU | Zig result | Go result |
|---|---:|---:|---:|---:|
| 80 clients, 1600 WSS frames | 1.08 s | 1.00 s | 80/80 | 80/80 |
| 128 clients, 2560 WSS frames | 1.80 s | 1.80 s | 128/128 | 128/128 |
| Four 8 MiB transfers | 0.32 s | 0.51 s | 2.609 MiB/s | 2.444 MiB/s |

The handshake workload shows no Zig CPU runaway. The sustained transfer used
37% less process CPU than Go in this x86 run, consistent with the earlier MIPS
field result favoring Zig's ChaCha20-only REALITY policy.
