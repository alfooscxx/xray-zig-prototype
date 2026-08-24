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
- Resolver-backed DNS by default, with opt-in IPv4 and IPv6 FakeDNS through the local `dns` inbound.
- SOCKS inbound for tests and manual probes.
- Domain, IP CIDR, and `inboundTag` routing.
- Ordered DNS resolver rules with required `resolver` and `outboundTag` fields.
- VLESS over raw TCP REALITY with `xtls-rprx-vision`.
- TLS 1.3 and TLS 1.2 with no ECH or GREASE ECH.
- Optional `chacha20-only` REALITY policy for software-AES targets.
- `freedom`, `blackhole`, and minimal TCP `dns` outbounds.
- Experimental IPv4/IPv6 TCP-only `tun` inbound on Linux.

The runtime uses lazily created 1 MiB-stack workers. Its default 512 MiB memory
budget derives the worker and raw-reactor limits instead of imposing a fixed
worker cap; explicit environment limits remain supported. Workers do not
retire before process shutdown. The runtime also has listener backpressure and
a 32-session VLESS/REALITY handshake limit. See
`docs/vision-response-deadlock.md` before changing the connection lifecycle.
The DNS inbound processes at most 16 queries concurrently. Each selected query
uses DNS-over-TCP through its rule's `outboundTag`; see `docs/dns-servfail.md`.

Missing or intentionally out of scope:

- UDP proxying and UDP Vision modes.
- xHTTP, gRPC, WebSocket, and other Xray transports.
- Full Xray JSON compatibility.
- TProxy and general-purpose firewall setup. The active GL-MT6000 TUN service
  owns one documented live-only nftables/policy-routing profile outside UCI.
- Server mode.

Redirect selects the original-destination socket option from the listener's
bind family; see `docs/ipv6-original-destination.md`. Resolver-backed DNS sends
each query over TCP through its selected outbound; see `docs/dns-servfail.md`.
Runtime objects use the general-purpose allocator so completed raw-reactor
connections are released; see `docs/raw-reactor-memory-leak.md`.

## Build And Test

The supported compiler is Zig 0.16.0 at `/usr/local/bin/zig`.

```sh
zig build
zig build test
zig build e2e-dns -Doptimize=ReleaseFast
zig build run -- check -config tests/fixtures/minimal-socks.json
zig build run -- check -config field-config-test.json
XRAY_BIN=/tmp/codex-xray-bin/xray XRAY_ZIG_REALITY_TRAFFIC=1 zig build e2e-reality
zig fmt src tests
```

For REALITY, TLS, or Vision changes, run unit tests, the real-Xray e2e harness,
and the deterministic delayed-preface field regression documented in
`docs/vision-response-deadlock.md`.

## Field Router Access

The active field router is the AArch64 GL.iNet GL-MT6000 at the static SSH
destination `root@192.168.8.1`. Always use
`ROUTER_SSH=root@192.168.8.1` for field-router SSH and SCP operations. Do not
infer or substitute the target from the default gateway, and do not use HTTP
administration endpoints, command injection, RCE helpers, FTP, or legacy
deployment scripts.

The old MIPS router is now only an optical bridge. Do not deploy binaries or
configs to it, run tests or commands on it, install packages, or change its
routes, firewall, services, or boot state. Access it only when the user
explicitly requests work on the bridge itself.

Before any field write or test, use SSH for a read-only identity check and stop
unless the target reports AArch64. Keep test artifacts and state under a unique
temporary path, preserve existing services, and remove temporary processes,
addresses, routes, and files afterwards. Firewall and boot changes require an
explicit user request. See `docs/router-field-access.md`.

Build the active router artifact with:

```sh
zig build -Dtarget=aarch64-linux-musl -Dcpu=cortex_a53 -Doptimize=ReleaseFast --prefix zig-out-aarch64-release
```

Verify the artifact is an AArch64 statically linked ELF before publishing it.
MIPS builds in older documents are historical benchmark instructions, not a
deployment target.

The active deployment runs `/etc/init.d/xray-zig` under `procd`, keeps both
SOCKS and `xray0` TUN inbounds, and uses the live-only rules documented in
`docs/openwrt-tun-service.md`. Do not write the TUN rules into `/etc/config`
unless the user explicitly requests persistent UCI firewall configuration.

## Coding Style

Use Zig formatter output. Keep modules protocol-owned, parsers strict, errors
explicit, and comments limited to non-obvious behavior. Use `redirect`, not
`dokodemo-door`. Unsupported config modes must fail validation rather than be
silently ignored.

Use `apply_patch` for manual edits. Do not commit build output, caches, logs, or
Python bytecode. Keep documentation current when changing config fields,
TLS/REALITY policy, Vision behavior, or concurrency limits.

## Commits

Use concise area-prefixed subjects such as `VLESS: Forward payload while waiting
for response`. Include commands run and call out protocol or config compatibility
changes in commit messages or pull requests.
