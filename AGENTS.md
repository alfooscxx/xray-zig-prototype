# Repository Guidelines

## Project Structure

This is an independent Zig project. Run build, test, format, and fixture
commands from this directory.

- `build.zig`, `build.zig.zon`: Zig build and package metadata.
- `src/config/`: native JSON parsing and validation.
- `src/core/`: runtime assembly, dispatch, and outbound selection.
- `src/dns/`: FakeDNS, DNS wire helpers, and resolver selection.
- `src/net/`: session types, stream wrappers, and the raw reactor.
- `src/proxy/`: redirect, DNS, SOCKS, VLESS, freedom, and blackhole protocols.
- `src/routing/`: ordered domain, IP, and inbound-tag rules.
- `src/transport/`: REALITY and TLS implementation.
- `tests/fixtures/`: native config fixtures.
- `tests/e2e/`: local real-Xray REALITY harness.
- `tests/field/`: real-server load and regression harnesses.
- `docs/`: architecture, Vision failure records, and performance results.

## Current Runtime State

Supported:

- IPv4 and IPv6 transparent TCP `redirect` inbounds.
- IPv4 and IPv6 FakeDNS through the local `dns` inbound.
- SOCKS inbound for tests and manual probes.
- Domain, IP CIDR, and `inboundTag` routing.
- Ordered DNS resolver rules with required `resolver` fields.
- VLESS over raw TCP REALITY with `xtls-rprx-vision`.
- TLS 1.3 and TLS 1.2 with no ECH or GREASE ECH.
- Optional `chacha20-only` REALITY policy for software-AES targets.
- `freedom`, `blackhole`, and minimal TCP `dns` outbounds.

The runtime uses 1 MiB stacks, a 128-worker cap, listener backpressure, and a
32-session VLESS/REALITY handshake limit. See
`docs/vision-response-deadlock.md` before changing the connection lifecycle.

Missing or intentionally out of scope:

- UDP proxying and UDP Vision modes.
- xHTTP, gRPC, WebSocket, and other Xray transports.
- Full Xray JSON compatibility.
- TUN/TProxy and iptables/ip6tables setup.
- Server mode.

Go Xray still owns production router NAT. The current MIPS artifact is
2,235,120 bytes with MD5 `326c49769032e93f911af9f5855e801e`; it is published
to the VPS but has not been deployed to or validated on the router.

## Build And Test

The supported compiler is Zig 0.16.0 at `/usr/local/bin/zig`.

```sh
zig build
zig build test
zig build run -- check -config tests/fixtures/minimal-socks.json
zig build run -- check -config field-config-test.json
XRAY_BIN=/tmp/codex-xray-bin/xray XRAY_ZIG_REALITY_TRAFFIC=1 zig build e2e-reality
zig fmt src tests
```

For REALITY, TLS, or Vision changes, run unit tests, the real-Xray e2e harness,
and the deterministic delayed-preface field regression documented in
`docs/vision-response-deadlock.md`.

Build the router artifact with:

```sh
zig build -Dtarget=mips-linux-musleabi -Dcpu=mips32r2 -Doptimize=ReleaseFast --prefix zig-out-mips-release
mkdir -p zig-out-mips/bin
mips-linux-gnu-strip --strip-all -o zig-out-mips/bin/xray-zig zig-out-mips-release/bin/xray-zig
```

Verify `readelf -A` reports MIPS32r2 and soft float before publishing.

## Coding Style

Use Zig formatter output. Keep modules protocol-owned, parsers strict, errors
explicit, and comments limited to non-obvious behavior. Use `redirect`, not
`dokodemo-door`. Unsupported config modes must fail validation rather than be
silently ignored.

Use `apply_patch` for manual edits. Do not commit build output, caches, logs, or
Python bytecode. Keep documentation current when changing config fields,
TLS/REALITY policy, Vision behavior, concurrency limits, or deployment status.

## Commits

Use concise area-prefixed subjects such as `VLESS: Forward payload while waiting
for response`. Include commands run and call out protocol or config compatibility
changes in commit messages or pull requests.
