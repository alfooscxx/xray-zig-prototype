# xray-zig

`xray-zig` is a standalone Zig prototype for a small, native-config subset of Xray client behavior. It is intentionally not a drop-in Xray JSON parser: unsupported fields should fail validation instead of being silently accepted.

## Project Layout

- `build.zig`, `build.zig.zon`: self-contained Zig build metadata.
- `src/main.zig`: CLI entry point for `check`, `run`, and `version`.
- `src/root.zig`: module root used by tests and the executable.
- `src/config/`: native JSON parsing and validation.
- `src/core/`: runtime assembly, routing lookup, and inbound dispatch.
- `src/dns/`: FakeDNS allocation, DNS wire helpers, and upstream resolver selection.
- `src/net/`: session target types, outbound stream wrappers, and sniffing helpers.
- `src/proxy/`: inbound and outbound protocol implementations.
- `src/routing/`: domain, IP, and inbound-tag outbound selection.
- `src/transport/`: REALITY and TLS ClientHello/record handling.
- `tests/fixtures/`: small configs used by parser/runtime checks.
- `tests/e2e/reality-xray.sh`: opt-in harness against a real Xray binary.
- `tests/field/`: mixed HTTPS, sustained-transfer, fragmented-WSS, and router-resource harnesses.
- `contrib/xray-zig-quick`: `wg-quick`-style process and transparent-firewall controller.
- `docs/`: protocol notes and implementation plans.

The current failure records are `docs/vision-response-deadlock.md`,
`docs/dns-servfail.md`, `docs/ipv6-original-destination.md`, and
`docs/raw-reactor-memory-leak.md`.

## Build And Test

Run commands from this directory:

```sh
zig build
zig build test
zig build run -- check -config tests/fixtures/minimal-socks.json
zig build run -- check -config field-config-test.json
```

If `zig` is not on `PATH`, use:

```sh
zig build test
```

The real Xray REALITY harness is opt-in:

```sh
XRAY_BIN=/tmp/codex-xray-bin/xray zig build e2e-reality
XRAY_BIN=/tmp/codex-xray-bin/xray XRAY_ZIG_REALITY_TRAFFIC=1 zig build e2e-reality
zig build e2e-dns -Doptimize=ReleaseFast
```

The second command also sends SOCKS traffic through the Zig client to the Xray server.

Remote workloads use a SOCKS inbound and do not require transparent routing:

```sh
XRAY_ZIG_SOCKS_PROXY=socks5h://192.168.1.1:21080 tests/field/http-matrix.sh
XRAY_ZIG_SOCKS_PROXY=socks5h://192.168.1.1:21080 tests/field/sustained-transfer.sh
python3 tests/field/fragmented-wss.py --target-host VPS_IP --server-name VPS_IP.nip.io
python3 tests/field/fragmented-wss.py --target-host VPS_IP --server-name VPS_IP.nip.io --clients 1 --post-connect-delay 750
```

The WSS server is `tests/field/wss-echo-server.py`. It is a temporary sidecar and does not require restarting or reconfiguring Xray. See `docs/performance.md` for benchmark results and a matched Go comparison.
The delayed command deterministically exercises the empty initial Vision frame that previously deadlocked while waiting for the VLESS response. See `docs/vision-response-deadlock.md` for symptoms, root cause, and before/after evidence.

For Cortex-A53 arm64 OpenWRT targets with the AES and PMULL CPU features, use
the CPU-specific build so Zig selects its hardware AES-GCM implementation:

```sh
zig build -Dtarget=aarch64-linux-musl -Dcpu=cortex_a53 -Doptimize=ReleaseFast --prefix zig-out-arm64-release
```

See [`docs/arm64-aes-gcm.md`](docs/arm64-aes-gcm.md) for disassembly checks,
router measurements, Firefox cipher ordering, and the Safexcel/AF_ALG result.

## Current Runtime Scope

Supported:

- Transparent TCP `redirect` inbounds for IPv4 and IPv6.
- Experimental real Linux TUN inbound with an IPv4/IPv6 TCP-only userspace endpoint.
- Local `dns` inbound with IPv4 and IPv6 FakeDNS integration.
- SOCKS inbound for tests and manual probes.
- VLESS outbound over raw TCP with REALITY.
- `xtls-rprx-vision` client flow for VLESS over REALITY.
- Firefox 148-compatible TLS ClientHello generation with TLS 1.3 and TLS 1.2 enabled and no ECH/GREASE ECH extension.
- Explicit REALITY cipher policy, including a ChaCha20-only mode for CPUs without fast AES.
- REALITY certificate authentication using the derived auth key.
- `freedom`, `blackhole`, and minimal TCP `dns` outbounds.
- Routing by domain, IP CIDR, and inbound tag, with required `routing.defaultOutboundTag`.
- DNS resolver selection by ordered domain rules. Every rule requires
  `outboundTag`; the final rule must be `domains: ["domain:"]`.

Out of scope for now:

- UDP proxying and UDP Vision modes.
- xHTTP, gRPC, WebSocket, and other Xray transports.
- Full Xray JSON compatibility.
- Automatic TUN routes, TProxy setup, and live iptables/ip6tables integration.
- Server mode.

## Native Config Notes

The config format is explicit and narrower than Xray JSON:

- Outbounds must have unique tags.
- `routing.defaultOutboundTag` is required.
- DNS servers use `resolver`, not Xray's `address`.
- DNS servers require `outboundTag`; queries use DNS-over-TCP through that
  outbound. A VLESS/REALITY outbound encrypts the resolver traffic without DoH.
- DNS rules are evaluated top to bottom; first matching `domains` rule wins.
- FakeDNS is opt-in through `dns.fakeDns`. Without it, A and AAAA queries are forwarded to the selected resolver.
- When enabled, FakeDNS uses `ipPool` for A answers and `ipPool6` for AAAA answers. Their defaults are `198.18.0.0/15` and `fc00::/18`.
- VLESS REALITY users may set `flow: "xtls-rprx-vision"`.
- REALITY `cipherPolicy` defaults to `"firefox"`. Set it to `"chacha20-only"` on software-AES targets. This changes the advertised cipher-suite fingerprint and requires server-side ChaCha20 support, but still offers TLS 1.3 and TLS 1.2 and never offers ECH.
- `redirect` is the supported transparent inbound protocol; `dokodemo-door` is not accepted.
- `tun` uses `settings.name`, optional `mtu`, and optional
  `maxConnections`; it never installs addresses, routes, firewall rules, or
  boot hooks. See [`docs/tun-inbound.md`](docs/tun-inbound.md).

`field-config-test.json` is a real-server client fixture for the current native API. `field-config-test-server.json` records the matching Xray server-side config used for interoperability testing.

## Developer Notes

Format after edits:

```sh
zig fmt src tests
```

Keep tests close to the module being changed. For transport or Vision behavior, run both `zig build test` and the real Xray e2e harness with `XRAY_ZIG_REALITY_TRAFFIC=1`.

For DNS changes, run `zig build e2e-dns -Doptimize=ReleaseFast`. The harness
verifies bounded concurrent DNS-over-TCP through explicit outbound dispatch.

Performance must be measured with `-Doptimize=ReleaseFast`; the default Debug build is intentionally not optimized. See `docs/performance.md` for the current real-server CPU, throughput, latency, and memory baseline.

The active field router is an AArch64 GL.iNet GL-MT6000. Build its artifact
with:

```sh
zig build -Dtarget=aarch64-linux-musl -Dcpu=cortex_a53 -Doptimize=ReleaseFast --prefix zig-out-aarch64-release
```

Verify the result is an AArch64 statically linked ELF. Field access is SSH-only;
see [`docs/router-field-access.md`](docs/router-field-access.md). The old MIPS
router is an optical bridge and is not a deployment or test target. MIPS
commands in dated performance documents describe historical measurements only.

For a router deployment, [`contrib/xray-zig-quick`](contrib/xray-zig-quick)
provides transactional `check`, `up`, `status`, and `down` commands around the
xray-zig process and its IPv4/IPv6 transparent firewall rules. See
[`docs/xray-zig-quick.md`](docs/xray-zig-quick.md) for the device profile and
installation procedure.

The executable creates a bounded Zig `Io.Threaded` runtime rather than using
the standard unlimited concurrent pool. Workers have 1 MiB stacks, are created
lazily, and remain until process shutdown. The default 512 MiB process budget
derives the worker and raw-reactor capacities instead of applying a fixed
worker ceiling; `XRAY_ZIG_MEMORY_BUDGET_MIB`, `XRAY_ZIG_WORKER_LIMIT`, and
`XRAY_ZIG_RAW_CONNECTION_LIMIT` can override the sizing inputs. Full pools
apply listener backpressure instead of resetting accepted clients, and at most
32 VLESS/REALITY handshakes run at once. TUN uses three concurrent tasks per
active proxied flow plus one shared retransmission timer. The 1 MiB stack is
retained because smaller stacks previously corrupted deep TLS workers; stack
pages are demand-paged and do not become RSS merely because the capacity is
large.
