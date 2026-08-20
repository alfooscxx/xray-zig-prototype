# Experimental FakeDNS SK_LOOKUP Inbound

The Linux-only `sk_lookup` inbound sends TCP connections for exact FakeDNS
addresses to ordinary kernel listeners. Linux owns the handshake,
retransmission, congestion control, reassembly, PMTU handling, and established
socket state; the experimental TUN TCP stack is not involved.

```text
DNS query -> FakeDNS lease -> BPF address map
                                  |
client packet -> local route -> SK_LOOKUP -> kernel listener -> Dispatcher
```

This is an ingress and control-plane improvement. Established payload still
passes through userspace and the existing VLESS/REALITY/Vision or freedom
implementation.

## Configuration

`sk_lookup` has no top-level `listen` or `port`. Both listener families are
required:

```json
{
  "tag": "ebpf-in",
  "protocol": "sk_lookup",
  "settings": {
    "listen4": "0.0.0.0",
    "port4": 19080,
    "listen6": "::",
    "port6": 19081,
    "maxMapEntries": 65536
  }
}
```

No other `sk_lookup` fields are accepted. Listener addresses must have the
indicated family. Ports are nonzero, and `maxMapEntries` is bounded from 1 to
1,048,576. A `sk_lookup` inbound requires `dns.fakeDns`.

FakeDNS accepts `reuseGraceSeconds`, which defaults to 30:

```json
"fakeDns": {
  "ipPool": "198.18.0.0/15",
  "ipPool6": "fc00::/18",
  "ttl": 60,
  "reuseGraceSeconds": 30
}
```

An address lease remains valid until DNS expiry plus this grace interval. It
cannot be reused while a dispatched TCP session holds it. Reuse increments its
generation. A refresh keeps the address and generation but extends both DNS
expiry and route validity. If allocation or BPF publication fails, the DNS
inbound returns SERVFAIL and never exposes an unroutable synthetic address.

## BPF Ownership And Ordering

xray-zig creates HASH maps for exact IPv4 and IPv6 addresses and one SOCKMAP
containing the two listener sockets. Values contain `domain_id`, `generation`,
and monotonic `route_valid_until_ns`. The SOCKMAP is only a listener-selection
table; it does not redirect established payload.

The SK_LOOKUP program accepts TCP only, requires an exact address-map hit whose
deadline has not expired, and calls `bpf_sk_assign`. It releases every socket
reference returned by the SOCKMAP lookup. Non-TCP traffic, unknown families,
misses, expired entries, missing listeners, and assignment failures are
fail-open (`SK_PASS`).

The runtime uses `bpf()` syscalls directly. It has no dependency on bpftool or
libbpf, does not pin objects, and does not use CO-RE or BTF. The process owns
all map, program, and link FDs. Closing the link FD, including on process exit,
detaches the namespace hook and removes the non-persistent objects.

Startup creates both listeners and attaches the link before connecting the
FakeDNS publisher and before DNS can answer. Publication completes before the
DNS response. `getsockname` on the accepted socket recovers the original fake
address and port. A refcounted lease keeps its stable domain record alive for
the complete synchronous Dispatcher call. The userspace `Session` remains the
frozen routing authority.

xray-zig itself does not install routes. Test harnesses add exact addresses;
the GL-MT6000 service wrapper owns the production FakeDNS prefix routes and
the matching dnsmasq lifecycle described in `openwrt-tun-service.md`.

## Isolated Router Tests

Build the static AArch64 artifacts on the host:

```sh
zig build -Dtarget=aarch64-linux-musl -Dcpu=cortex_a53 \
  -Doptimize=ReleaseFast --prefix zig-out-aarch64-release
zig build ebpf-lab-peer -Dtarget=aarch64-linux-musl -Dcpu=cortex_a53 \
  -Doptimize=ReleaseFast --prefix zig-out-aarch64-release
```

After the SSH identity check documented in `router-field-access.md`, upload
the artifacts and harnesses to one unique `/tmp` directory. The router needs
`ip-full`, `kmod-veth`, `bpftool`, and `/dev/net/tun`.

The correctness harness uses two network namespaces and one veth pair:

```sh
./ebpf-sk-lookup-lab.sh /tmp/UNIQUE/xray-zig /tmp/UNIQUE/ebpf-lab-peer
```

It proves IPv4 and IPv6 exact hits, a pre-publication fail-open miss, monotonic
expiry while the stale map key is retained, TUN coexistence, and removal of
the owned link, program, maps, TUN, veth, and namespaces. All network
operations have bounded deadlines.

The WAN harness adds a second veth whose root end joins `br-lan`; the isolated
router namespace becomes an ordinary DHCP LAN client. It reuses existing
LAN-to-WAN forwarding and NAT without adding or changing firewall rules. The
test-client namespace has no default route and can reach only its exact
FakeDNS routes:

```sh
./ebpf-sk-lookup-wan.sh /tmp/UNIQUE/xray-zig /tmp/UNIQUE/config.json
```

The test configuration must omit unsupported settings and route both FakeDNS
resolution and default traffic through the intended VLESS outbound. HTTPS
uses the real hostname and SNI, verifies the public CA chain, and requires the
VLESS established event for every flow plus at least one Vision raw-handoff
event before reporting success. Direct-copy selection is controlled by the
remote Vision peer and is not a per-flow SK_LOOKUP correctness condition.

Safety invariants are deliberate:

- no root-namespace default, policy, or FakeDNS route is added;
- no firewall table or rule is changed;
- the live xray-zig service, listeners, configuration, and TUN are not used;
- the lab TUN has no address or route;
- no BPF object is pinned; and
- all processes, files, interfaces, and namespaces belong to one invocation.

## Field Validation

The isolated correctness and WAN harnesses passed on the AArch64 GL-MT6000
running OpenWrt 25.12.5 and Linux 6.12.94. The correctness run covered both
address families, miss and expiry fail-open behavior, exact map contents, TUN
coexistence, and complete object cleanup.

The WAN run resolved a real FakeDNS address and downloaded a verified HTTPS
payload from `speed.cloudflare.com` through SK_LOOKUP, VLESS, REALITY, inner
TLS, Vision `CommandDirect`, and the existing userspace raw reactor. This proves
the end-to-end path but is not a throughput comparison with TUN.

The merge gate then ran eight concurrent verified HTTPS downloads of 8 MiB
each. All eight exact bodies completed through eight established VLESS
sessions. Six flows reached bidirectional Vision raw handoff; two remained on
the valid userspace Vision path because the remote peer did not set
`read_direct`. The final pre-merge run reported 67,108,864 bytes in 3 seconds
and 139 process CPU ticks. These Internet/CDN figures are diagnostic rather
than a reproducible performance benchmark.

The production cutover then installed the same SK_LOOKUP artifact alongside
the existing TUN cache-drain fallback. A temporary LAN network namespace
resolved both A and AAAA through the router and completed a verified 1 MiB
HTTPS download through VLESS/REALITY/Vision. The service was stopped before
commit: the test required removal of the BPF program, FakeDNS routes and DNS
upstream plus restoration of dnsmasq rebind protection. After a service start,
the complete dataplane and a second verified LAN HTTPS download had to pass.
A third post-commit flow logged the domain target and Vision raw handoff.

## Current Limits

- TCP only; UDP requires a separate capability and original-destination test.
- Local FakeDNS routes remain an operator responsibility outside the documented
  GL-MT6000 service wrapper.
- Established payload remains in userspace after SK_LOOKUP.
- Flow metadata maps, TC observability, and kernel socket-to-socket payload
  redirection are separate future work.
- A controlled TUN-versus-SK_LOOKUP benchmark is required before making a
  production performance claim.
