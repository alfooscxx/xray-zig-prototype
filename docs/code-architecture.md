# Code Architecture

This document describes how the Zig client is organized and where protocol behavior belongs.

## Runtime Flow

1. `src/main.zig` parses CLI arguments and loads a JSON config for `check` or `run`.
2. `src/config/mod.zig` parses the native config subset into typed structs and validates cross-reference constraints such as outbound tags and routing defaults.
3. `src/core/mod.zig` builds the runtime from the parsed config, starts inbounds, and owns the dispatcher used by inbound handlers.
4. Inbounds convert accepted sockets into `net.Session` values and call `session.Dispatcher`.
5. The dispatcher uses `src/routing/mod.zig` to select an outbound tag, then invokes the matching outbound implementation.
6. Outbounds connect to the target or proxy server and bridge traffic until EOF, cancellation, or an error.

The runtime intentionally keeps protocol parsing close to the protocol module. Shared code should live in `src/net/`, `src/dns/`, or a protocol-owned helper only when more than one module needs it.

Configuration and CLI data use the process-lifetime arena. Runtime-owned
objects that are destroyed individually use a thread-safe allocator. FakeDNS
uses `init.gpa`; raw-reactor connections use `std.heap.page_allocator`. Each
reactor connection contains two 16 KiB buffers, so releasing one unmaps its
pages instead of leaving them in the ReleaseFast SMP allocator's caches. Do
not pass an arena allocator to the raw reactor: arena `destroy` is a no-op.

## Runtime Concurrency

`src/main.zig` owns a bounded `Io.Threaded` instance with 1 MiB worker stacks.
Workers are created only when concurrency is needed, so the configured
capacity does not allocate all stacks or their RSS at startup. Zig 0.16 keeps
created workers until `Io.Threaded.deinit`, however, so a burst leaves a warm
pool and its touched stack pages resident. Do not replace it with `init.io`:
the default pool is unlimited and reserves 16 MiB per worker. Smaller 256 KiB
and 512 KiB stacks previously corrupted deep TLS/crypto workers, so reducing
the stack is not used as an RSS optimization.

The heavy-worker and raw-reactor limits cover different connection states. Lowering
the worker limit does not increase reactor capacity: it reduces the number of
connections that can initialize or remain in a non-direct bridge. The
runtime-owned REALITY semaphore bounds the CPU-heavy handshake phase. Its
`XRAY_ZIG_REALITY_HANDSHAKE_LIMIT` setting defaults to 32 and can be raised
independently of established-connection capacity.
`XRAY_ZIG_MEMORY_BUDGET_MIB` defaults to 512 MiB. The runtime models an
initialization worker as 560 KiB and a raw connection as 112 KiB, reflecting
the measured approximately 5:1 resident-memory ratio. Without explicit caps it
derives both limits directly from the budget while reserving five raw slots per
worker: 512 MiB selects 468 workers and 2,340 raw slots, while 70 MiB selects
64 and 320. The pool and raw connection buffers are both lazy; these values are
admission ceilings, not startup allocations.

`XRAY_ZIG_WORKER_LIMIT` and `XRAY_ZIG_RAW_CONNECTION_LIMIT` override automatic
sizing. When an explicit worker limit omits the raw limit, raw capacity is five
times the worker request. Explicit requests that exceed the budget are reduced
proportionally. One low-level io_uring shard is bounded to 4,095 raw bridges;
larger explicit raw requests fail instead of silently changing admission. The
selected counts are logged as `heavy_workers` and
`io_uring_raw_connections`; the selected handshake limit is logged as
`reality_handshakes`.
This model is an admission-sizing estimate, not an allocator-enforced RSS
limit; the watchdog remains responsible for terminating a process that exceeds
the same budget. The process raises its soft descriptor limit to the permitted
hard limit before starting the runtime. Each raw connection still requires two
file descriptors and two 16 KiB buffers, so field validation must sample both
FD use and RSS.

The legacy small-router controller requests 80 workers and 240 raw connections
within its explicit 70 MiB budget. A 64/320 field run passed all traffic but
emitted 126 worker-capacity warnings. The 80/240 run passed the same 32-request mixed
HTTPS matrix and four 4 MiB transfers, emitted 16 warnings, and reached 5.342
MiB/s. The final 0.0.5 run repeated 32/32 and 4/4, reached 5.678 MiB/s, emitted
four warnings, and peaked at 37.1 MiB RSS. A 96/160 run eliminated capacity
warnings and reached 5.778 MiB/s, but two successive mixed matrices each lost
one Fastly TLS handshake. The 80/240 split is therefore the production default
pending longer observation.

Each accepted TCP connection gets one handler worker for routing and outbound
initialization. Framed TLS/Vision work remains on that worker, while eligible
plain and post-Vision direct-copy bridges hand both sockets to the shared raw
reactor and release it. If the pool limit is reached, a TCP inbound holds one
accepted stream, retries scheduling every 10 ms, and leaves later connections
in the kernel listen backlog. It must not run the handler synchronously on the
accept worker because initialization or a non-offloaded connection would stall
that listener indefinitely.

The TUN endpoint uses a temporary flow-owner task until it has a routing
preface, then one dispatcher task while the selected outbound performs
handshake and framed Vision work. A protocol-owned low-level io_uring handles
both bridge directions, partial writes, half-closes, TCP retransmission, and
idle expiry for every flow. Once Vision hands the dispatch side to the shared
raw reactor, an established TUN flow retains no per-flow worker. The earlier
three-task and five-task designs remain recorded in
`tun-tcp-field-test-2026-08-20.md` as historical baselines.

The response-header phase has a 60-second inactivity timeout, and established
worker and raw-reactor bridges have a 300-second inactivity timeout. These
match Xray-core's default handshake and connection-idle policy. Without these
bounds, speculative TCP opens and abandoned half-open sessions can permanently
consume every handler worker or raw-reactor slot even while RSS remains below
the watchdog threshold. Version 0.0.6 added these timeouts after a production
process reached all 80 workers and approximately 540 open descriptors while
remaining below its RSS limit.

Connections that have completed the Vision direct-copy transition, plus plain
freedom connections that are not eligible for kernel offload, move to the
shared raw reactor. Producers publish them
through a lock-free atomic stack and signal an `eventfd`; there is no producer
spin lock. The reactor submits one receive and one send per direction through a
low-level Linux io_uring and uses one one-second timeout for idle expiry and
cooperative cancellation. `Io.Threaded` remains the bounded heavy executor;
high-level `std.Io.Uring` is not used because Zig 0.16 reserves a fixed 60 MiB
virtual stack per fiber and its stream listen/accept/read/write vtable is still
unimplemented. Reactor shutdown closes the ring, canceling all kernel buffer
references, before active or pending connection storage is freed.

An optional Linux-only backend can move eligible connections originating from
the `sk_lookup` inbound into a pair of SOCKHASH maps. Vision waits for its
strict bidirectional direct-copy gate and drains all userspace buffers first.
Freedom has no transformation gate: the `sk_lookup` session has an empty
preface, so it attempts admission immediately after target resolution and TCP
connect, before constructing a userspace writer or entering the raw reactor.
SOCKS, redirect, TUN, recursively dispatched DNS, and every other inbound leave
`allow_sockhash_offload` false and therefore cannot enter this path. Passive
targets are installed before programmed sources, and an identity SK_SKB parser
drives pre-existing receive queues through the verdict path. Its manager owns
duplicate FDs, FIN/RST/idle handling, exact non-LRU state, and teardown.
Admission pressure falls back to the io_uring raw reactor only when ordering
safety permits it; see `ebpf-sk-lookup.md`.

Inbound startup and error messages share one buffered writer, protected by an `Io.Mutex`. Any new concurrent log site must use the same mutex.

## Config Layer

`src/config/mod.zig` is the only place that should accept JSON field names. It should reject unsupported modes early with typed errors. The current config is a native API, not Xray compatibility mode.

Important rules:

- `routing.defaultOutboundTag` is required.
- Outbounds must be tagged.
- DNS server entries require `resolver` and `outboundTag`.
- DNS domain selection is ordered and first-match wins.
- The last DNS server rule is the catch-all and must be `domains: ["domain:"]`.
- VLESS REALITY supports only raw TCP security `reality`.

Keep parser tests next to parser changes so fixture behavior and validation errors stay visible.

## Core And Routing

`src/core/mod.zig` validates runtime combinations that require multiple config sections. It also wires the inbound dispatcher to outbound handlers.

`src/routing/mod.zig` evaluates rules in config order. Supported matchers are:

- `inboundTag`
- `domain`
- `ip`

If no rule matches, `routing.defaultOutboundTag` is used.

## DNS

`src/dns/protocol.zig` handles DNS wire parsing and A/AAAA response writing. `src/dns/fakedns.zig` owns the optional independent IPv4 and IPv6 FakeDNS pools and reverse mappings. DNS TTL controls advertisement freshness; a mapping remains authoritative until its address is actually replaced after the reuse quarantine. Without `dns.fakeDns`, the DNS inbound selects the first matching resolver rule, frames the query as DNS-over-TCP, and dispatches it through its rule's `outboundTag`. A `vless` tag therefore protects DNS with REALITY without exposing direct DoH. With FakeDNS enabled, reverse-mapped `freedom` targets are resolved through the same selected DNS rule before the direct connection is opened; they must not use the host resolver, which could return the synthetic address again. `src/dns/client.zig` owns routed DNS-over-TCP exchange and direct-target resolution, while `src/dns/upstream.zig` owns resolver address parsing. On Linux, the DNS client connects its caller and dispatcher with a local `AF_UNIX` socket pair, avoiding a temporary loopback TCP listener per query. Other platforms retain the loopback TCP fallback.

The experimental Linux `sk_lookup` inbound is documented in
`ebpf-sk-lookup.md`. FakeDNS uses stable domain records and refcounted leases;
when its optional bpffs persistence is configured, startup reconstructs those
records from validated pinned address/metadata maps before attaching the new
namespace link. The metadata map is control-plane-only and has no dataplane
lookup cost. Listener and dataplane SOCKHASH maps are never restored across a
process boundary. The BPF publisher runs before the DNS response, while an accepted session holds
its lease across the complete synchronous dispatch.

DNS server selection should not be implemented in protocol code. Protocol code should ask the DNS config/upstream layer for the selected resolver based on the queried domain.

## Network Session Model

`src/net/session.zig` defines:

- `Target`: either an IP address or a domain plus port.
- `Session`: target metadata plus inbound tag and optional sniffed domain.
- `OutboundConnection`: plain or REALITY-wrapped stream abstraction.

`OutboundConnection.read` is expected to be a short read suitable for live proxying. In particular, the REALITY implementation must return already-decrypted buffered TLS plaintext before waiting for more network input.

## Proxy Modules

Each protocol owns its wire format:

- `src/proxy/redirect/inbound.zig`: transparent TCP accept and original destination lookup.
- `src/proxy/dns/inbound.zig`: DNS inbound request handling.
- `src/proxy/socks/inbound.zig`: SOCKS5 test/manual inbound.
- `src/proxy/tun/inbound.zig`: Linux TUN ownership, bounded TCP flow state,
  and `AF_UNIX` stream adaptation for the dispatcher.
- `src/proxy/tun/packet.zig`: IPv4/IPv6 TCP parsing, packet construction,
  per-family MSS, and checksum handling.
- `src/proxy/vless/outbound.zig`: VLESS request/response headers and REALITY connection setup.
- `src/proxy/vless/vision.zig`: Vision padding, unpadding, TLS detection, and direct-copy state tracking.
- `src/proxy/freedom/outbound.zig`: direct TCP outbound.
- `src/proxy/blackhole/outbound.zig`: discard outbound.
- `src/proxy/dns/outbound.zig`: minimal TCP DNS outbound.

Protocol modules should return explicit errors for unsupported modes instead of ignoring config fields.

## REALITY And TLS

`src/transport/reality/client.zig` prepares the REALITY ClientHello session id, derives the auth key, and wraps a TCP stream with the TLS client.

VLESS limits concurrent TCP plus REALITY initialization to 32 sessions. This bounds CPU and outbound ClientHello bursts without reducing established bridge capacity; the semaphore permit is released as soon as REALITY setup completes.

`src/transport/tls/client_hello.zig` builds Firefox-like ClientHello bytes. Current policy:

- TLS 1.3 and TLS 1.2 are offered.
- ECH and GREASE ECH are never emitted.
- Firefox-like fingerprints are supported; generic `firefox` maps to the Firefox 148 no-ECH profile.
- `realitySettings.cipherPolicy` defaults to `firefox`. The explicit `chacha20-only` policy restricts TLS 1.3 and TLS 1.2 suites to ChaCha20 for software-AES CPUs; it intentionally changes the cipher-suite portion of the browser fingerprint.

On AArch64, Zig selects AES instructions and PMULL-backed GHASH at compile
time. Builds for Cortex-A53 OpenWRT routers must pass `-Dcpu=cortex_a53`;
generic AArch64 builds retain the software AES fallback. Field measurements
and the kernel Safexcel/AF_ALG status are in `docs/arm64-aes-gcm.md`.

`src/transport/tls/client.zig` is a small TLS client used by REALITY. REALITY certificate verification checks the Ed25519 certificate signature as `HMAC-SHA512(public_key, auth_key)`, matching Xray's REALITY client behavior.

## Vision Flow

VLESS Vision handling is split in two:

- `src/proxy/vless/outbound.zig` writes the VLESS header, waits up to 500 ms for initial client bytes, writes the first Vision frame, then polls both sides while incrementally reading the VLESS response header.
- `src/proxy/vless/vision.zig` handles Vision framing for both directions.

The initial 500 ms wait mirrors Xray's behavior. If no client bytes arrive, an empty long-padding frame is sent so the VLESS header is camouflaged. While the response header is pending, later client bytes must still be Vision-encoded and flushed; otherwise an empty initial frame can deadlock with a server waiting for target payload. See `docs/vision-response-deadlock.md` for the failure artifact and regression command.

If the input is TLS, the initial reader consumes exactly one complete record. The uplink pump continues assembling complete TLS records until Vision switches to direct copy; socket read boundaries must not become Vision frame boundaries. It performs at most one socket read per readiness event and preserves an incomplete record in connection state, returning to the bidirectional poll loop between fragments. Waiting synchronously for the rest of an inner TLS record prevents downlink progress and stalls interactive HTTPS and WebSocket sessions.

TLS classification is incremental in both directions. The client side retains only the six-byte ClientHello prefix, and the server side streams TLS record, ServerHello, and extension headers through a small state machine. Large extensions such as post-quantum hybrid key shares are skipped without buffering the complete ServerHello. This avoids both socket-read-boundary dependence and the former 1 KiB ServerHello limit, which left modern TLS 1.3 connections on the blocking Vision bridge instead of handing them to the raw reactor.

After a TLS 1.3 application-data record triggers Vision `CommandDirect`, the final command frame is flushed through outer REALITY/TLS. Subsequent writes use the raw TCP stream, while the reader first drains decrypted and socket-buffered bytes before switching to raw reads. Network pumps use single `readVec` calls so small TLS records are forwarded without waiting for a full 16 KiB buffer.

## Testing Strategy

Use three levels of tests:

- Unit tests next to changed Zig modules for parser, routing, DNS, TLS, and Vision helpers.
- Fixture checks with `zig build run -- check -config tests/fixtures/<name>.json`.
- Real Xray e2e with `XRAY_BIN=/tmp/codex-xray-bin/xray XRAY_ZIG_REALITY_TRAFFIC=1 zig build e2e-reality`.

For real remote probes that cannot use transparent `redirect` without root network setup, wrap the same `proxy` outbound in a temporary SOCKS inbound and test with `curl --socks5-hostname`.

`tests/field/` contains reusable router workloads:

- `http-matrix.sh` runs bounded mixed-origin HTTPS concurrency.
- `sustained-transfer.sh` measures fixed-byte throughput.
- `fragmented-wss.py` drives TLS through `SSLObject`/`MemoryBIO`, splits encrypted records into configurable TCP fragments, and can delay TLS after SOCKS CONNECT to force the empty-preface regression path.
- `wss-echo-server.py` is the dependency-free temporary TLS/WebSocket sidecar.
- `router-sample.sh` records process jiffies, RSS, threads, FDs, sockets, and reclaimable memory, with `start`, `summary`, and `stop` modes.

Keep persistent firewall changes out of these harnesses. Any reverse-FakeDNS or transparent comparison rule must be exact, workstation-scoped, inserted manually for one probe, and deleted immediately afterward.
