# Experimental SK_LOOKUP Inbound

The Linux-only `sk_lookup` inbound is an experimental TCP dataplane. It sends
connections for exact FakeDNS addresses, and optionally policy-routed IP
literals, to ordinary kernel TCP listeners. The
kernel therefore owns the handshake, retransmission, congestion control,
reassembly, PMTU handling, and established socket state; the experimental TUN
TCP stack is not involved in this path.

```text
DNS query -> FakeDNS lease -> BPF address map
                                  |
client packet -> local /32 or /128 route -> SK_LOOKUP -> kernel listener
                                                        |
                                                   Dispatcher
                                                        |
                                               freedom or VLESS
```

The process must run with the privileges needed to create and attach BPF
objects in its current network namespace. If any map, program, helper, or link
operation is unsupported, startup fails. There is no silent redirect or TUN
fallback.

## Configuration

`sk_lookup` has no top-level `listen` or `port`. Both listener families are
currently required:

```json
{
  "tag": "ebpf-in",
  "protocol": "sk_lookup",
  "settings": {
    "listen4": "0.0.0.0",
    "port4": 19080,
    "listen6": "::",
    "port6": 19081,
    "maxMapEntries": 65536,
    "fakeDnsPersistence": {
      "pinDirectory": "/sys/fs/bpf/xray-zig"
    },
    "sockhashOffload": {
      "mode": "required",
      "maxFlows": 1024,
      "idleTimeoutSeconds": 300
    },
    "transparentIntercept": {
      "ingressInterface": "br-lan",
      "excludedIPs": ["192.168.8.0/24", "fe80::/10"],
      "proxyServerIPs": ["203.0.113.9", "2001:db8::9"]
    }
  }
}
```

`fakeDnsPersistence` is optional and disabled by default. Its only field is an
absolute, normalized `pinDirectory`. The directory must already exist on a
mounted bpffs; xray-zig does not create a mount or choose a machine-specific
path. See [Restart-Safe FakeDNS](#restart-safe-fakedns) below.

`sockhashOffload` is optional and disabled by default. When present, its only
supported mode is `required`: startup fails if the kernel cannot create the
maps, load the SK_SKB programs, or attach them. `maxFlows` defaults to 1024 and
is bounded to 1 through 131,072. `idleTimeoutSeconds` defaults to 300 and is
bounded to 1 through 86,400. Per-flow allocation or admission pressure falls
back to the existing raw reactor when this is still ordering-safe; it does not
make startup support optional.

`transparentIntercept` is optional. Without it, behavior remains FakeDNS-only.
With it, a no-lease destination is assigned only when it arrived on the named
interface and does not match an exclusion. The name is resolved to an ifindex
at startup; a missing interface is fatal. `excludedIPs` and `proxyServerIPs`
are required non-empty arrays. Proxy-server entries must be exact addresses,
not CIDRs. The configured FakeDNS pools use separate BPF LPM tries from the
operator exclusions. Consequently, a missing address in a FakeDNS pool is
dropped rather than reinterpreted as a literal or passed to a local wildcard
listener.

No other `sk_lookup`, `fakeDnsPersistence`, `sockhashOffload`, or
`transparentIntercept` fields are accepted. The listener
addresses must have the indicated family. Ports are nonzero and
`maxMapEntries` is bounded to 1 through 1,048,576. A `sk_lookup` inbound also
requires `dns.fakeDns`.

FakeDNS accepts `reuseGraceSeconds`, which defaults to one day:

```json
"fakeDns": {
  "ipPool": "198.18.0.0/15",
  "ipPool6": "fc00::/18",
  "ttl": 600,
  "reuseGraceSeconds": 86400
}
```

DNS expiry marks an address as no longer recently advertised. After the
additional reuse grace it becomes eligible for replacement, but its domain
mapping and exact BPF element remain authoritative until another allocation
actually replaces that address. It cannot be replaced while a dispatched TCP
session holds it. Replacement increments its generation; a refresh keeps the
address and generation while extending DNS expiry and the reuse quarantine.
If the pool is exhausted, the BPF map is full, or publication fails, the DNS
inbound returns SERVFAIL and does not expose a synthetic address that the
dataplane cannot route.

## Ownership And Ordering

xray-zig creates two HASH maps for exact IPv4 and IPv6 addresses, two LPM tries
for the configured FakeDNS pools, one SOCKMAP for the listener sockets, and a
nine-entry per-CPU ARRAY named `xz_sk_count` for bounded monitoring counters.
Values in the address maps contain `domain_id`, `generation`, and the monotonic
`reuse_after_ns`; the packet program needs only the exact-map membership and
does not expire a published mapping by time.

The namespace receives one attached `xz_sk_lookup` dispatcher. It tail-calls a
small `xz_sk_fake` handler through the private `xz_sk_progs` PROG_ARRAY; an
exact-map miss outside the FakeDNS pools can tail-call the separate
`xz_sk_literal` handler when `transparentIntercept` is enabled. Tail-call
failure is fail-open only for destinations outside the FakeDNS pools. A pool
miss is terminal `SK_DROP`, so stale/missing leases cannot become literals or
reach ordinary local sockets.
FakeDNS and literal handling use separate listener lookup, assignment, and
release programs. A successful
FakeDNS assignment immediately executes `r0 = SK_PASS; BPF_EXIT`, with no
shared branch register, long jump, admission publication, monitoring helper,
or fallthrough into literal policy. Only the dispatcher is linked to the
network namespace; handler FDs are owned by the PROG_ARRAY and process.
Non-TCP traffic, unknown families, excluded destinations, and wrong ingress
interfaces remain fail-open (`SK_PASS`). A live FakeDNS assignment failure is
fail-closed, as is an exact-map miss inside either FakeDNS pool. A no-lease
destination outside the pools can reach the listener only through the
configured ingress interface. The counter map records hit, exact-map miss,
pool miss, IPv4/IPv6 assignment success and error, pass, and drop without
contended global updates;
the local control API aggregates it through the process-owned FD.

The runtime uses `bpf()` syscalls directly. It has no runtime dependency on
bpftool or libbpf and does not use CO-RE or kernel BTF. The program consists
only of stable UAPI context offsets and eBPF instructions. The process always
owns ephemeral listener SOCKMAP, program, and link FDs. Closing the link FD
detaches the namespace hook.

Startup creates both listeners and the BPF objects, restores the complete
FakeDNS store when persistence is configured, and only then attaches the BPF
link. DNS and SK_LOOKUP workers are spawned after restoration and attach.
Both listeners enable `IP_TRANSPARENT`/`IPV6_TRANSPARENT` before attachment.
This is required when the selected destination is made local only by a policy
route and is not assigned to an interface; without it `bpf_sk_assign` can
succeed while TCP cannot create the transparent request socket or SYN-ACK.
Publication to the metadata and address maps completes before the userspace
lease is committed and before a DNS response is sent. The accepted socket's
`getsockname` supplies the original fake local address and port. A FakeDNS
lease handle protects the normalized hostname for the complete synchronous
`Dispatcher` call. The userspace `Session` remains the source of the frozen
outbound decision; there is no correctness-critical LRU flow map.

An admitted literal uses the original address and port from `getsockname`, has
no sniffed domain, preserves the inbound tag and address-family preference,
and remains eligible for SOCKHASH. Ordered domain, CIDR, inbound-tag, and
default outbound selection stays in userspace. BPF selects only the inbound
listener.

Successful literal assignments also write a monotonic timestamp to a
bounded LRU admission map keyed by family, both addresses, and both ports. A
no-lease `accept` must consume a matching entry within 60 seconds before it can
reach the dispatcher. This prevents direct connections to the wildcard
listeners, or genuine local traffic missed by an operator exclusion, from
bypassing the ingress BPF policy. The entry is written only after
`bpf_sk_assign` succeeds; lookup is one-shot and expired entries fail closed.
FakeDNS sessions still require their live userspace lease and never use this
proof as a fallback.

The application does not install routes. Operators must add only the intended
FakeDNS prefixes or exact test addresses as local routes in the same namespace.

For literal interception, the intended routing is nftables marking of selected
LAN TCP, an `ip rule`, and a dedicated table with `local 0.0.0.0/0 dev lo` and
`local ::/0 dev lo`. Do not replace a production TUN route until a
source-scoped field test passes. Exclude router-local, management, and
link-local destinations before setting the mark, and repeat them in
`excludedIPs` as a second boundary. Every REALITY/proxy endpoint must use an
IP-literal address, be excluded from marking, and be listed in
`proxyServerIPs`. Hostname proxy endpoints are rejected while transparent
interception is enabled because a static exclusion cannot remain fail-closed
across DNS changes. Locally generated outbound sockets do not match the configured
ingress ifindex, while the explicit server exclusion protects against routing
mistakes and recursion. UDP is not admitted.

## Restart-Safe FakeDNS

With `fakeDnsPersistence`, xray-zig pins exactly three objects below the
configured directory:

```text
fake4       IPv4 HASH map used by SK_LOOKUP
fake6       IPv6 HASH map used by SK_LOOKUP
lease_meta  control-plane HASH map with BPF_F_NO_PREALLOC
```

The listener SOCKMAP, SK_LOOKUP program/link, and every SOCKHASH object remain
ephemeral. The packet program never references `lease_meta`, so persistence
adds no per-packet lookup. A metadata write precedes each address-map update;
the address map is the commit marker. Metadata keys include family, address,
domain ID, generation, and exact monotonic reuse deadline. Startup can
therefore retain the last committed version and prune an interrupted pending
version without guessing.

Each metadata value contains the normalized domain and DNS deadline. A reserved
header records the schema and a fingerprint covering both pool strings, TTL,
reuse grace, `maxMapEntries`, and schema version. Reopen validates map type,
key/value sizes, maximum entries, flags, names, header, and fingerprint. An
incompatible or incomplete set fails closed instead of being replaced. Pins
created by a failed live initialization are rolled back; a process crash in
the small multi-pin creation window can be recovered with the administrative
command below.

Unexpected `BPF_OBJ_GET` and every failed `BPF_OBJ_PIN` log the exact operation
stage, configured bpffs path, and numeric and symbolic errno. In particular,
`EEXIST` can identify a non-BPF file or directory occupying one of the fixed
pin names even when no reusable pinned map was opened.

A deterministic lock file named
`/run/xray-zig-fakedns-<sha256(pinDirectory)>.lock` is held with an exclusive
nonblocking lock for the runtime lifetime. xray-zig verifies `/run` is tmpfs,
opens the file with `CLOEXEC` and `NOFOLLOW`, creates it as mode 0600 when
absent, and accepts only a root-owned regular file with one link. The SHA-256
name isolates different normalized absolute pin directories without imposing
a filename-length limit. A second writer and administrative cleanup fail while
the runtime owns the file. The file is deliberately not unlinked on close:
unlinking a flock file permits two processes to lock different inodes under the
same name. `/run` clears it on reboot without a flash write.

Normal shutdown closes FDs but deliberately leaves the three bpffs pins and
retained mappings. On the next process start, every committed A/AAAA mapping
and generation is restored even when it is already eligible for reuse;
unreferenced transaction records are pruned. Allocation can replace an eligible
mapping later without colliding with restored addresses.
bpffs is RAM-backed: this preserves state across process restarts in one boot,
not across a kernel reboot, and causes no flash writes.

Persistence schema version 2 introduces durable-until-replaced mappings and is
intentionally incompatible with schema version 1. Stop the old process and run
the old binary's `fakedns-unpin` with its compatible configuration before
starting a binary that uses the new schema; incompatible pins are never deleted
automatically.

The metadata map capacity is twice `maxMapEntries` plus two transactional/header
slots, but `BPF_F_NO_PREALLOC` means memory is charged only for actual entries.
Allow roughly 0.35--0.5 KiB per live family lease, or about 0.35--0.5 MiB per
1000 single-stack names and 0.7--1.0 MiB when all 1000 names have both A and
AAAA leases.

Administrative disable/cleanup must be done after stopping the process that
uses the directory:

```sh
xray-zig check -config /path/to/config.json
xray-zig fakedns-unpin -config /path/to/config.json
```

`fakedns-unpin` acquires the same `/run` lock, validates every present exact object,
and removes only `fake4`, `fake6`, and `lease_meta`. Missing members are allowed
so it can recover an interrupted first creation; a foreign or incompatible
object is never unlinked. Removing `fakeDnsPersistence` from config does not
implicitly delete old pins, because that would make an accidental config edit
destructive.

A privileged restart acceptance test can record an A/AAAA answer, stop and
restart the same config, verify that the answer remains identical before its
monotonic deadline, and inspect the fixed pins:

```sh
bpftool map show pinned /sys/fs/bpf/xray-zig/fake4
bpftool map show pinned /sys/fs/bpf/xray-zig/fake6
bpftool map show pinned /sys/fs/bpf/xray-zig/lease_meta
```

During the stop interval the address maps remain pinned, but the namespace
link and listener map are gone, so cached addresses are not assigned to a dead
listener. After restart a new program/link and listener SOCKMAP use the reopened
address maps.

## Optional TCP SOCKHASH Offload

For VLESS, the SOCKHASH backend is used only after the existing Vision gate has
proved both directions are direct-copy, all Vision uplink bytes are flushed,
the client reader is empty, and `rawHandoffReady()` reports no REALITY/TLS
stream buffering. Direct freedom needs no protocol transformation and can be
admitted immediately after connect. A separate boolean capability on `Session`
is set only by the `sk_lookup` TCP inbound. SOCKS, redirect, TUN, DNS, and
recursively dispatched sessions cannot enter this backend even if their tags
happen to match. Non-Vision VLESS flows remain on their existing userspace
paths.

The backend deliberately uses two established-socket SOCKHASH maps:

```text
xz_sh_targets  passive redirect destinations, no attached program
xz_sh_sources  active receive sources, identity STREAM_PARSER + STREAM_VERDICT
```

For each flow, xray-zig first creates non-evicting peer, active-state, and
per-direction stats entries and inserts both sockets into `xz_sh_targets`.
Only then does it insert the receive sources. The verdict obtains the source
socket cookie, checks peer and active-flow state, and redirects to the passive
map with `bpf_sk_redirect_hash`. Missing peer/state/target entries are drops,
increment a redirect-error counter, and cause userspace to reset the flow;
there is no silent PASS into an unread socket queue.

This split is required for a zero-copy cutover on Linux 6.12. Inserting a
socket into a verdict map does not migrate data already in
`sk_receive_queue`. An identity stream parser causes `tcp_bpf_recvmsg_parser()`
to drive those queued skb through the parser/verdict path under the socket
lock. After each source insertion xray-zig performs a nonblocking `MSG_PEEK`
kick. `EAGAIN` proves that queued bytes were redirected without being consumed;
EOF is recorded for half-close handling. Once both source kicks have completed,
an initially observed FIN is propagated to the peer before the flow is
published to the monitor; this keeps redirected payload ordered before FIN. A
returned payload means the cutover invariant failed and the connection is
reset rather than risking reordered fallback data.

If the second source cannot be inserted after the first was activated, the
first direction remains in BPF and the ordinary raw reactor services the other
direction. A single cleanup callback owns that hybrid flow. It removes active
sources first, marks state inactive, removes both passive targets, then removes
peer/stats/state entries before the raw reactor closes its duplicate FDs. If
the hybrid transfer itself cannot be admitted, the flow is reset; it is never
silently restarted as a two-direction raw flow after bytes may have been
redirected.

Fully offloaded flows are monitored through duplicate FDs. The BPF program
updates per-direction bytes, monotonic `last_seen_ns`, redirect errors, and the
persistent `xz_sh_total` ARRAY counters. Userspace propagates FIN as
`shutdown(peer, SHUT_WR)`, permits the opposite half to continue, propagates
RST, enforces the configured monotonic idle timeout, and deletes exact map
entries before closing its sockets. Process shutdown drains both full and
hybrid ownership paths. The two SK_SKB programs are attached to
`xz_sh_sources` with owned `BPF_LINK_CREATE` FDs
(`BPF_LINK_TYPE_SOCKMAP`). Closing the verdict and parser link FDs detaches
them before their programs and maps are closed. No SOCKHASH object is pinned
and no libbpf, CO-RE, or BTF is used. Linux 6.12 supports this link type in
`sock_map_link_create()`; stream-parser attachment additionally requires the
target kernel's `CONFIG_BPF_STREAM_PARSER`.

Vision admission is logged as `sockhash-handoff`; direct freedom admission is
logged as `freedom sockhash-handoff`. Safe ordinary fallback is logged as
`raw-reactor-handoff` with its reason, while partial hybrid and fail-closed
cutover outcomes are unambiguous. On full teardown, `sockhash-close` reports an
`owner` (`vless_vision`, `freedom`, or `generic`), both BPF byte counts,
aggregate redirect errors, and reset status.

Freedom has a shorter cutover gate than Vision. Only `Session` values emitted
by the `sk_lookup` inbound set `allow_sockhash_offload`, and that inbound always
dispatches an empty preface. After FakeDNS reversal, resolver-backed address
selection, and successful TCP connect, freedom admits the untouched client and
upstream sockets directly. It does not create a writer and does not publish a
fully admitted flow to the raw reactor. A non-empty preface disables freedom
admission defensively; the preface is completely flushed before the ordinary
raw-reactor handoff. SOCKS, redirect, TUN, and recursive DNS sessions do not set
the authorization bit, even when they select the same freedom outbound.

The cutover design follows the kernel's
[SOCKMAP/SOCKHASH documentation](https://docs.kernel.org/bpf/map_sockmap.html)
and Linux 6.12's
[`tcp_bpf_recvmsg_parser()` implementation](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/tcp_bpf.c),
which explicitly drives an existing receive queue through the parser under the
socket lock. Multiple-map socket ownership and program compatibility follow
Linux 6.12
[`sock_map_link()`](https://github.com/torvalds/linux/blob/v6.12/net/core/sock_map.c).
The privileged capability selftest remains the required proof that the target
router accepts the same socket simultaneously in the passive and programmed
maps and exhibits the expected queued-data and FIN behavior.

## Isolated Router Lab

Build the static AArch64 artifacts on the host:

```sh
zig build -Dtarget=aarch64-linux-musl -Dcpu=cortex_a53 \
  -Doptimize=ReleaseFast --prefix zig-out-aarch64-release
zig build ebpf-lab-peer -Dtarget=aarch64-linux-musl -Dcpu=cortex_a53 \
  -Doptimize=ReleaseFast --prefix zig-out-aarch64-release
zig build ebpf-sockhash-selftest -Dtarget=aarch64-linux-musl -Dcpu=cortex_a53 \
  -Doptimize=ReleaseFast --prefix zig-out-aarch64-release
```

After the operator performs the SSH identity check from
`router-field-access.md`, upload the two binaries and
`tests/field/ebpf-sk-lookup-lab.sh` to one unique `/tmp` directory. The router
needs `ip-full`, `kmod-veth`, `bpftool`, and `/dev/net/tun`. Run the harness with
absolute paths:

```sh
./ebpf-sk-lookup-lab.sh /tmp/UNIQUE/xray-zig /tmp/UNIQUE/ebpf-lab-peer
```

The harness creates this topology:

```text
xz-client-$PID netns             xz-router-$PID netns
  lab client ---- veth ---- DNS + separate xray-zig
                              |-- SK_LOOKUP link/maps/listeners
                              |-- xztun0 (no address and no route)
                              `-- deterministic DNS/IPv4/IPv6 echo peer
```

It adds only namespace-local routes for `198.18.254.1/32` and
`fd00:7872:6179:eb9f::1/128`. Before DNS publication it proves that a TCP SYN
to the locally routed IPv4 address is not assigned. It then performs DNS
allocation followed by real IPv4 and IPv6 TCP echo flows and uses exact
`bpftool map lookup ... key hex` operations to prove that both address maps
contain their published key. The lab uses a short TTL and reuse grace, retains
the IPv4 map entry, waits until it is eligible for replacement, and proves that
a new connection still uses the retained mapping. Before publication, the same
locally routed address must increment both the pool-miss and drop counters. It
also verifies the BPF
objects and idle test TUN, kills only the process it started, verifies
link/map/TUN removal, and deletes both namespaces. All client operations have
both an internal five-second network deadline and a shell watchdog. Traps apply
the same cleanup on failure.
The harness removes its own nested `/tmp/xz-ebpf-lab-$PID` state. The SSH
orchestration that uploaded the binaries and script must remove that separate
operator-created upload directory after the run.

### Transparent Literal Lab

Upload `tests/field/ebpf-sk-lookup-literals-lab.sh` beside the same two AArch64
artifacts. After the required read-only AArch64 identity check, the exact field
command is:

```sh
/tmp/UNIQUE/ebpf-sk-lookup-literals-lab.sh \
  /tmp/UNIQUE/xray-zig /tmp/UNIQUE/ebpf-lab-peer
```

This harness does not stop or inspect the production service. It snapshots
same-named BPF object IDs and identifies only objects newly created by its
process. It gives the isolated process a unique control socket below its lab
directory and waits for `status` to report `ready=true` before the first probe.
Three unique namespaces contain an authorized client, a wrong-ingress
client, and an isolated router. Only the authorized veth has an `iif` policy
rule to a namespace-local table containing `local 0.0.0.0/0 dev lo` and
`local ::/0 dev lo`; no root-namespace route or firewall rule is changed.

The bounded run proves verifier/load for SK_LOOKUP and required SOCKHASH,
authorized IPv4/IPv6 literals, direct CIDR and default blackhole decisions,
wrong-ingress and direct-listener admission-proof rejection, excluded local
CIDR and exact proxy-server addresses, live and missing IPv4/IPv6
FakeDNS, a freedom SOCKHASH handoff, and removal of every newly observed
program and map ID. FakeDNS checks first perform and print a bounded DNS-only
allocation, then probe the published address separately so DNS failures and
SK_LOOKUP failures remain distinguishable. Before each live FakeDNS probe it
requires an exact `bpftool map lookup` for the published IPv4/IPv6 key and
captures the raw lease value plus per-CPU SK_LOOKUP counters before and after
the SYN. It also captures the loaded xlated BPF program, monotonic/boottime
snapshots, policy rules/routes, and authorized-veth packet counters. A
60-second lab TTL keeps the live-hit diagnosis bounded; the separate
FakeDNS-only lab proves that a mapping remains usable after becoming eligible
for reuse. Expected-negative client errors are
captured in the lab directory and printed only when the harness itself fails.
Both live FakeDNS allocations/connections are now the first dataplane actions
after verifier/load and object discovery. Literal, missing-lease, blackhole,
exclusion, admission-proof, and SOCKHASH probes run only afterward, ruling out
earlier flow state as a cause of a live FakeDNS failure.
The live IPv4 and IPv6 probes also run bounded numeric `tcpdump` captures on
the isolated router veth, including TCP flags and sequence/acknowledgement
numbers; captures are flushed and printed on failure. The router therefore
needs `tcpdump` in addition to the previously listed lab dependencies.
All processes, rules, links, addresses, routes, files, and
namespaces belong to the temporary namespaces and are removed by the EXIT
trap. Expected final output is:

```text
PASS: isolated transparent literals v4/v6, ingress proof, exclusions, FakeDNS, routing, SOCKHASH, and cleanup
```

For a FakeDNS-only control with the same rebuilt binaries, run immediately
afterward from the same unique upload directory:

```sh
/tmp/UNIQUE/ebpf-sk-lookup-lab.sh \
  /tmp/UNIQUE/xray-zig /tmp/UNIQUE/ebpf-lab-peer
```

That harness now snapshots same-named production BPF IDs and selects only its
new namespace-owned program/maps, and it also uses a unique control socket. It
does not require stopping the production service.

### Privileged SOCKHASH Capability Selftest

`tests/field/ebpf-sockhash-selftest.sh` creates one temporary network namespace
with loopback only and runs the separate `ebpf-sockhash-selftest` artifact
under a 30-second watchdog. The executable creates real TCP pairs, queues data
in both receive queues before source insertion, proves exact prequeue/postqueue
ordering in both directions, proves both client-first and upstream-first
payload-plus-FIN queued before admission, permits the opposite peer to respond
after each half-close, and then proves RST propagation on another flow. It
fails unless admission is full SOCKHASH; hybrid/raw fallback is not
accepted. The wrapper checks fixed BPF names for collisions before start,
removes only its namespace, and requires all owned program/map names to be gone
after process exit.

```sh
./ebpf-sockhash-selftest.sh /tmp/UNIQUE/ebpf-sockhash-selftest
```

Safety invariants are deliberate:

- no root-namespace default, policy, or FakeDNS route is added;
- no firewall table or rule is read or changed;
- the live xray-zig process, configuration, listeners, and TUN are never
  inspected, signaled, or used;
- the lab TUN has no address or route, so test traffic cannot enter it;
- no BPF object is pinned; and
- all names, processes, files, veth devices, and namespaces belong to the one
  harness invocation.

## Field Validation (2026-08-20)

The isolated harness passed on the AArch64 GL-MT6000 running OpenWrt 25.12.5
and Linux 6.12.94. It used the documented two-network-namespace topology with
one veth pair and did not use the live xray-zig dataplane. The first field
verifier run found that the socket reference returned by the SOCKMAP lookup
must be released after `bpf_sk_assign`; both address-family paths now call
`bpf_sk_release` after every assignment attempt.

The original run passed IPv4 and IPv6 exact FakeDNS hits but deliberately left
pre-publication misses and monotonic expiry fail-open. That behavior was
superseded after a stale Google FakeDNS address reached the router's wildcard
HTTPS listener. The current harness instead requires fail-closed pool misses
and durable mappings after the reuse deadline. An idle test TUN coexisted in
the same isolated router namespace without owning test routes. Process
shutdown removed the owned BPF link, program, maps, and test TUN, and the
harness removed both namespaces and their veth state.

The 2026-08-25 rerun on the same AArch64 router and Linux 6.12.94 passed the
new contract: an unpublished IPv4 pool address incremented `pool_miss` and
`drop`, published IPv4/IPv6 addresses completed echo flows, and the IPv4
mapping still completed a flow after the short lab TTL and reuse grace. The
transparent-literal harness then passed both FakeDNS families, IPv4/IPv6
literal routing, wrong-ingress and exclusion rejection, SOCKHASH handoff, and
owned BPF-object cleanup. The production service remained ready with all four
listeners active.

### SOCKHASH Capability Result

The upstream router kernel initially failed this gate with `EOPNOTSUPP` because
`CONFIG_BPF_STREAM_PARSER` was disabled. The 2026-08-21 field image retained
Linux 6.12.94 and enabled `CONFIG_BPF_STREAM_PARSER`, `CONFIG_STREAM_PARSER`,
and `CONFIG_NET_SOCK_MSG`. This is a compile-time kernel capability; installing
another bpftool package cannot substitute for it.

On that image the earlier privileged capability selftest passed full dual-map
admission, data queued before and after source insertion, exact ordering in
both directions, post-admission half-close, RST propagation, and owned-object
cleanup. The updated selftest additionally covers payload plus FIN queued on
either side before admission. It must be rerun on the target kernel; a
successful updated run reports:

```text
PASS: SOCKHASH prequeue/order/pre-admission-half-close/reset capability selftest
PASS: isolated SOCKHASH capability selftest and owned-object cleanup
```

Required mode then started in production with both owned SK_SKB links and all
SOCKHASH state maps present. The existing persistent FakeDNS maps retained
their IDs across the restart. A temporary DHCP LAN namespace completed an
8 MiB certificate-verified HTTPS download through
FakeDNS -> SK_LOOKUP -> VLESS/REALITY/Vision -> SOCKHASH. The corresponding
flow logged `sockhash-handoff`, transferred 8,398,062 BPF bytes during the
bounded run, and increased redirect errors by zero. The same run separately
validated an exact `example.com` route through the userspace `freedom` path.
The implementation now admits eligible `sk_lookup` freedom sessions directly
after connect; that newer path still requires an isolated field run before it
is considered router-validated.

### Isolated WAN/VLESS Validation

`tests/field/ebpf-sk-lookup-wan.sh` extends the same topology with a second
temporary veth pair. Its root end is attached to `br-lan`, while the router
namespace end obtains a DHCP lease and becomes an ordinary LAN client. This
reuses the router's existing LAN-to-WAN forwarding and NAT without adding or
changing firewall rules. The test-client namespace still has no default route;
it can reach only the exact FakeDNS routes through the isolated router
namespace.

On 2026-08-20 this harness used a temporary configuration derived from the
field VLESS/REALITY profile, with both routing default and catch-all DNS set to
the `proxy` outbound. An initial real UDP FakeDNS query was followed by a TCP
connection to `198.18.254.1:80`, an HTTP/1.1 request for `example.com`, and an
Internet response with status 200. The lab client received 863 bytes in its
first response read. The isolated xray-zig log independently contained
`vless ... established target=example.com:80 client_tls=false`:

```text
PASS WAN HTTP example.com 198.18.254.1:80 status=200 first_bytes=863
PASS: isolated FakeDNS -> SK_LOOKUP -> VLESS/REALITY -> WAN HTTP
```

A subsequent HTTPS run used OpenWrt's `uclient-fetch` inside the test-client
namespace. A mount private to `ip netns exec` supplied the lab DNS server as
that process's resolver, preserving the real URL hostname and SNI without
changing `/etc/resolv.conf`. The system CA bundle verified the origin
certificate. The client downloaded exactly 1 MiB from
`speed.cloudflare.com` through `198.18.254.1:443`. Before reporting success,
the harness required both of these isolated xray-zig events:

```text
vless ... established target=speed.cloudflare.com:443 client_tls=true
vision ... raw-reactor-handoff target=speed.cloudflare.com:443 tls=true tls12=true xtls=true write_direct=true read_direct=true
```

The observed result was:

```text
PASS WAN HTTPS speed.cloudflare.com 198.18.254.1:443 bytes=1048576 certificate=verified
PASS: isolated FakeDNS -> SK_LOOKUP -> VLESS/REALITY/Vision -> WAN HTTPS raw handoff
```

These earlier runs prove the real WAN TCP path through FakeDNS, SK_LOOKUP, VLESS,
REALITY, inner TLS, Vision `CommandDirect`, and the existing raw-reactor
handoff. They do not imply a SOCKHASH handoff.
Each run released its DHCP client, deleted both namespaces and veth pairs, and
removed the test BPF objects and TUN. The operator also removed the temporary
credential-bearing configuration and upload directory after each run.

### SOCKHASH A/B Load Harness

`tests/field/ebpf-sockhash-ab.sh` runs the isolated WAN harness twice with
separate namespaces and cleanup: first a control config without
`sockhashOffload`, then an otherwise equivalent required-offload config. Its
defaults are eight concurrent verified HTTPS downloads of 8 MiB per arm and a
180-second whole-batch watchdog. `SOCKHASH_LOAD_CONCURRENCY`,
`SOCKHASH_DOWNLOAD_BYTES`, and `SOCKHASH_LOAD_TIMEOUT_SECONDS` can override
those bounds.

The WAN harness snapshots same-name production BPF object IDs before each arm,
selects only the newly created test objects, and requires those new IDs to be
gone while every baseline ID remains present after cleanup. This permits the
isolated namespace test to coexist with the live service without signaling it
or relying on globally unique BPF object names.

Each flow has a unique output file and certificate verification must succeed.
The control requires at least N `raw-reactor-handoff` events. The candidate
requires both SK_SKB programs, both SOCKHASH maps, all non-evicting state maps,
N `sockhash-handoff` and `sockhash-close` events, zero close errors, summed
upstream BPF bytes at least equal to the downloaded body total, persistent
`xz_sh_total` bytes at least equal to that total, and zero aggregate redirect
errors. It then requires every captured SOCKHASH program/map ID to disappear.
Both arms report total bytes, elapsed wall seconds, approximate throughput, and
the xray-zig process's user+system CPU ticks from `/proc/$pid/stat`.

```sh
./ebpf-sockhash-ab.sh \
  /tmp/UNIQUE/xray-zig \
  /tmp/UNIQUE/control.json \
  /tmp/UNIQUE/sockhash.json
```

This is a correctness-oriented field comparison, not a reproducible Internet
benchmark: origin/CDN load, WAN congestion, and connection placement vary
between arms. Production evidence still needs repeated interleaved trials or a
controlled origin.

On 2026-08-20 one control arm completed all eight concurrent verified HTTPS
downloads and required all eight raw-reactor handoffs:

```text
PASS WAN HTTPS speed.cloudflare.com flows=8 bytes=67108864 elapsed_s=8 throughput_Bps=8388608 cpu_ticks=122 certificate=verified offload=0
```

The immediately following required-offload candidate stopped during startup
with the `CONFIG_BPF_STREAM_PARSER` failure above, before creating any HTTPS
client. It therefore produced no candidate throughput or CPU measurement and
must not be compared numerically with the control.

Two surrounding control attempts also exposed why these Internet numbers are
only diagnostic. They established all eight VLESS connections but reached the
two-direction Vision handoff gate on 7/8 and 6/8 flows respectively. The latter
attempt still downloaded eight exact 8 MiB bodies with successful certificate
verification; two completed through the ordinary Vision userspace path with
`write_direct=true` and `read_direct=false`. The harness rejected both attempts
as impure raw-reactor baselines. A controlled peer that deterministically emits
both Vision direct commands is required for a repeatable offload benchmark.

After the compatible kernel was installed, a trace-enabled four-flow control
run localized this impurity before SOCKHASH admission. Two flows received
server `CommandDirect` and entered the raw reactor. The other two decoded only
valid Vision `continue` frames until EOF: one captured at least 67 continue
frames and the other at least 26, with no direct frame. All four downloaded
exact 8 MiB bodies. Xray's server Vision writer applies `IsCompleteRecord()` to
the current `MultiBuffer` but does not accumulate a fragmented inner TLS record
across calls. Under concurrent Internet traffic it can therefore safely retain
Vision framing for the entire connection. A client must not infer direct mode
when the server did not send the command.

The production smoke test avoids treating that server decision as an offload
failure: it retries a bounded number of certificate-verified HTTPS connections
until one is gate-eligible, then requires its `sockhash-handoff`, a clean close
with at least the body size in upstream BPF bytes, and zero redirect errors.
The 2026-08-21 run reached the gate on its first attempt and passed with an
8 MiB body. Deterministic performance comparison still requires a controlled
Vision server that guarantees both direct commands.

## Staged Roadmap And Current Limits

1. The current TCP correctness phase is implemented for exact IPv4/IPv6
   FakeDNS hits, fail-closed pool misses, durable mappings, and owned-object
   cleanup. This does not by itself establish production performance or every
   failure mode.
2. Optional TC per-CPU counters and events may add observability only after an
   interface-selection and configuration contract is defined. TC is not part
   of the current correctness path.
3. UDP requires a separate kernel-capability and original-destination selftest
   for UDP `sk_lookup` before any userspace UDP implementation is designed.
   VLESS Vision UDP remains out of scope unless XUDP/Mux is implemented.
4. Any flow metadata map is for observability and diagnostics. The userspace
   `Session` remains the frozen routing authority unless a demonstrated race
   establishes the need for additional correctness state.
5. The optional SOCKHASH post-`rawHandoffReady` backend is implemented as an
   experimental, required-at-startup mode. Unit state-machine tests cover FIN
   orders, half-close response, reset, idle, capacity, cleanup ownership, and
   bounded ordering; the privileged capability and A/B harnesses are the
   required field gates for real parser/queue/backpressure behavior. The field
   router's Linux 6.12.94 image now passes the kernel capability gate and a
   production WAN smoke test. Non-gate-eligible Vision connections correctly
   remain on the userspace path, so uncontrolled Internet A/B runs must report
   gate eligibility separately from SOCKHASH admission success.
6. The kernel-socket path and SOCKHASH offload must be benchmarked against the
   TUN/raw-reactor control path for correctness, CPU cost, and latency before
   production use.
