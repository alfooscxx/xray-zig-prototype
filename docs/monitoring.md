# Monitoring And Observability Plan

## Goals

Monitoring must explain both whether the router and process are healthy and why
proxy traffic is succeeding, slowing down, or failing. System metrics alone can
show CPU, memory, file descriptor, socket, and interface pressure, but they
cannot expose routing decisions, DNS and FakeDNS state, REALITY/Vision phases,
or BPF fallback behavior.

The monitoring design therefore has three independent data owners:

- OpenWrt exports host, process, interface, route, and conntrack state.
- xray-zig exports protocol and runtime semantics known only to the process.
- eBPF programs, when enabled, update bounded counters and map state that
  xray-zig aggregates. Per-CPU maps are preferred for future high-rate
  counters when measurements justify them.

The proxy should not contain a general-purpose web server or a full web UI.
Instead, it should expose a local control and metrics API over a Unix socket.
OpenWrt adapters can present that API through LuCI, ubus, and Prometheus.

```text
xray-zig
  |-- internal counters, gauges, and fixed histograms
  `-- /run/xray-zig/control.sock
          |
          |-- xray-zig ctl status|top|dns|route|bpf|diag
          |-- rpcd/ubus adapter -> luci-app-xray-zig
          `-- Prometheus collector/exporter

OpenWrt
  |-- system metrics from procfs, netifd, and conntrack
  `-- prometheus-node-exporter-lua or collectd

External workstation, NAS, or VPS
  `-- Prometheus/VictoriaMetrics and Grafana
```

## Current Baseline (2026-08-21)

This document is a target contract, not a claim that the control socket,
Prometheus collector, ubus adapter, or LuCI application already exists. The
current implementation provides the following observability building blocks:

- FakeDNS, `sk_lookup`, VLESS/REALITY/Vision, raw-reactor, and SOCKHASH
  lifecycle events are available as low-rate process logs; there are no
  packet-by-packet events. The SOCKHASH close
  event records `owner=freedom|vless_vision|generic`, per-direction bytes,
  redirect errors, and reset state.
- Each active SOCKHASH direction has bounded `bytes`, `last_seen_ns`, and
  `redirect_errors` state in `xz_sh_stats`. `xz_sh_total` retains aggregate
  bytes, packets, and redirect errors for the process lifetime, independent of
  individual flow cleanup. These maps are not pinned and are recreated on
  every process start.
- The SOCKHASH userspace monitor owns duplicate socket FDs, observes FIN/RST,
  enforces idle timeout, and maintains exact flow capacity. It is lifecycle
  machinery rather than a general monitoring API.
- Persistent FakeDNS mode pins only `fake4`, `fake6`, and `lease_meta`.
  `lease_meta` contains domain metadata and must remain root-only. The pins
  survive a process restart, but the kernel objects do not survive a router
  reboot; the service then creates a new empty set.
- The field harnesses currently correlate process logs, exact BPF object IDs
  and map values, `/proc` CPU/RSS data, and verified client byte counts. The
  field router has passed SK_LOOKUP/FakeDNS correctness, the TCP SOCKHASH
  capability selftest, and a production Vision SOCKHASH HTTPS smoke test.
- Direct freedom SOCKHASH admission is implemented and locally validated with
  the complete test suite and AArch64 build. It still requires an isolated
  router field run before it becomes part of the production monitoring
  baseline.

There is no stable metrics registry or scrape endpoint yet. SK_LOOKUP has no
dedicated hit/miss/expiry counter map, no TC observability program is attached,
and no BPF ring buffer is present. Until the control API lands, logs and
`bpftool` are test evidence, not a stable integration contract.

## Ownership Boundaries

### OpenWrt And System Exporter

The system layer should own metrics that can be obtained accurately without
instrumenting xray-zig:

- system CPU time, load, memory, reclaimable memory, and pressure;
- process CPU time, RSS, thread count, file descriptors, and socket count;
- conntrack count and limit;
- interface bytes, packets, drops, and errors;
- link, address, and default-route availability;
- softnet drops, kernel allocation failures, and OOM events;
- wireless, thermal, and storage state when useful.

xray-zig should not duplicate these by periodically parsing its own procfs
files. `prometheus-node-exporter-lua` already provides lightweight OpenWrt
collectors for CPU, load, memory, conntrack, file descriptors, network devices,
and related system state.

### xray-zig

xray-zig must directly instrument information that cannot be reconstructed
reliably from procfs, thread names, or logs:

- inbound acceptance, dispatch, rejection, and active session counts;
- ordered routing decisions and selected outbound;
- DNS query concurrency, resolver selection, result, and latency;
- FakeDNS allocation, lookup, lease, expiry, and pool pressure;
- VLESS and REALITY initialization stages and failures;
- Vision classification and `CommandDirect` transitions;
- Vision gate eligibility separately from subsequent SOCKHASH admission;
- freedom and Vision SOCKHASH handoff, fallback, hybrid, and teardown by a
  bounded flow-owner enum;
- bytes handled through Vision framing, the raw reactor, or SOCKHASH;
- runtime capacity limits and saturation;
- normalized protocol errors and fallback reasons.

The current `src/diagnostics.zig` thread names remain useful for field debugging,
but they must not be the metrics interface. Inferring connection phases or raw
reactor counts from `/proc/<pid>/task/*/comm` is inherently approximate.

### eBPF

When the BPF dataplane is enabled, programs should update only bounded maps:

- per-CPU packet, byte, lookup, and action counters;
- map occupancy and update failures;
- `sk_lookup` hit, miss, expiry, assignment, pass, and drop counters;
- TC ingress action counters if TC or TCX is used;
- SOCKHASH packet, byte, redirect, and redirect-error counters;
- ring-buffer event loss.

Packet-by-packet ring-buffer events are prohibited. Ring buffers are for rare
diagnostic events such as socket assignment errors, inconsistent generations,
failed offload admission, or unexpected teardown. The metrics collector reads
and aggregates per-CPU maps at scrape time.

Live sockhash ownership must not depend on an LRU entry. Offloaded sockets need
explicit insertion, teardown, and capacity accounting.

The current `xz_sh_total` is a bounded shared ARRAY rather than a per-CPU map.
It is sufficient for correctness checks and low-rate snapshots. Conversion to
per-CPU counters should be justified by the monitoring A/B benchmark instead
of changing the proven dataplane preemptively. The metrics collector must read
maps through FDs already owned by xray-zig; production monitoring must not find
objects by global BPF name or assume stable kernel object IDs.

## xray-zig Metrics

The names below describe the intended stable contract. Labels must be bounded
by configuration or a small enum.

### Runtime And Connections

```text
xray_zig_build_info{version,dataplane}
xray_zig_ready
xray_zig_uptime_seconds

xray_zig_connections_active{network,stage}
xray_zig_connections_total{network,inbound,outbound,result}
xray_zig_connection_rejections_total{reason}
xray_zig_bytes_total{network,direction,path}
xray_zig_routing_decisions_total{outbound,rule,result}
```

Valid byte paths can include `vision_framed`, `raw_reactor`, `splice`, and
`sockhash`. These counters make loss of kernel offload visible instead of
silently treating it as a performance regression.

`splice` is reserved for a future implemented path and must not be emitted by
the current runtime. SOCKHASH ownership is reported separately under the BPF
metrics so freedom and Vision behavior cannot be conflated.

### DNS And FakeDNS

```text
xray_zig_dns_queries_total{qtype,resolver,result}
xray_zig_dns_duration_seconds_bucket{resolver,le}
xray_zig_dns_queries_active
xray_zig_dns_query_limit

xray_zig_fakedns_leases{family,state}
xray_zig_fakedns_pool_capacity{family}
xray_zig_fakedns_allocations_total{family,result}
xray_zig_fakedns_lookup_total{family,result}
```

Lease states should be a fixed set such as `active`, `stale`, and `reusable`.
Pool exhaustion, publication failure, expiry, and reverse-lookup miss must be
separate results.

### VLESS, REALITY, And Vision

```text
xray_zig_reality_handshakes_active
xray_zig_reality_handshakes_total{stage,result}
xray_zig_reality_handshake_duration_seconds_bucket{le}

xray_zig_vision_connections_active{phase}
xray_zig_vision_transitions_total{transition,result}
xray_zig_vision_gate_total{direction,result}
xray_zig_vision_bytes_total{direction,path}
xray_zig_raw_reactor_connections
xray_zig_raw_reactor_limit
```

Failure stages and transition results must be enums rather than error strings.
Useful REALITY stages include TCP connect, ClientHello, server response, VLESS
response header, and established. Vision phases should distinguish scanning,
framed transfer, raw handoff, and offloaded transfer. `vision_gate_total` must
distinguish `command_direct`, `continue_until_eof`, and protocol/error outcomes.
An origin that never sends `CommandDirect` is not a SOCKHASH admission failure.

### BPF

```text
xray_zig_bpf_program_up{hook}
xray_zig_bpf_lookup_total{hook,result}
xray_zig_bpf_socket_assign_total{family,result}
xray_zig_bpf_packets_total{hook,action}
xray_zig_bpf_bytes_total{hook,action}

xray_zig_bpf_map_entries{map}
xray_zig_bpf_map_capacity{map}
xray_zig_bpf_map_update_total{map,result}
xray_zig_bpf_events_dropped_total

xray_zig_bpf_offloaded_flows{network,owner}
xray_zig_bpf_offload_total{network,owner,result}
xray_zig_bpf_offload_fallback_total{network,owner,reason}
xray_zig_bpf_sockhash_bytes_total{network,owner,direction}
xray_zig_bpf_sockhash_packets_total{network}
xray_zig_bpf_sockhash_redirect_errors_total{network}
```

The bounded owner values are `freedom`, `vless_vision`, and `generic`. Admission
results distinguish `offloaded`, `raw_fallback`, `hybrid_raw`, and
`failed_closed`. Fallback reasons use the existing `FallbackReason` enum; raw
error strings must never become labels. Per-owner byte counters are finalized
from exact flow stats during userspace teardown, while the aggregate BPF map
provides an independent process-wide cross-check. `network` is the fixed
`tcp|udp` enum. The current SOCKHASH dataplane emits only `tcp`; reserving the
dimension avoids changing the contract if the separately gated UDP
`SK_SKB_VERDICT` design is later implemented.

The same status and metrics API must exist when BPF is disabled. In that case,
the dataplane is reported as `redirect`, `tun`, or another configured backend,
and BPF program gauges report no active hooks.

## Cardinality And Privacy

Prometheus metrics must never use the following as labels:

- domain names;
- client or fake IP addresses;
- five-tuples or connection identifiers;
- arbitrary error messages;
- dynamically generated map or rule names.

Allowed dimensions include configured inbound and outbound tags, configured
resolver identifiers, the fixed TCP/UDP network enum, address family, query
type, protocol stage, action, and a fixed result enum. Every additional label
must have a predictable upper bound.

Domains and flow details belong only in a bounded recent-event buffer or an
explicit diagnostic query. Access to them must require an authenticated LuCI
session and should be opt-in. Diagnostic bundles should redact credentials,
REALITY keys, client addresses, and domain history by default.

## Collection Cost

Instrumentation must remain cheap enough for the router dataplane:

- gauges and low-frequency events can use atomics;
- per-read byte accounting should be accumulated in connection-local state and
  periodically or finally added to global counters;
- histograms use fixed bucket arrays and no allocation;
- BPF uses per-CPU counters to avoid cross-CPU contention;
- rendering a snapshot must have a bounded response size and should not allocate
  per active connection;
- Prometheus scrapes should default to a 15- or 30-second interval.

The field performance suite should compare monitoring disabled and enabled. CPU
cost, throughput, RSS, and latency must not regress materially.

## Local Control API And CLI

xray-zig should own a root-controlled Unix socket:

```text
/run/xray-zig/control.sock
```

Initial read-only operations:

```text
status
metrics
recent-events
connections-summary
dns-test
route-test
bpf-status
diagnostic-snapshot
```

The protocol may be a small length-bounded request/response format or JSON
lines. It must reject unknown fields, cap request and response sizes, avoid
long-lived subscriptions initially, and never execute arbitrary commands.

The main binary can expose the API through a CLI frontend:

```sh
xray-zig ctl status
xray-zig ctl top
xray-zig ctl route example.com:443
xray-zig ctl dns example.com A
xray-zig ctl bpf
xray-zig ctl events --limit 50
xray-zig ctl diag
```

Process supervision, restart, firewall management, and WAN recovery do not
belong to this API. OpenWrt `procd`, netifd hooks, and a deployment service own
those operations. This separates the useful diagnostics from the legacy model
where one shell script combined monitoring, deployment, firewall changes, and
watchdog behavior.

## LuCI Interface

The web interface should be a separate `luci-app-xray-zig`. An rpcd ucode
adapter translates authenticated ubus methods into bounded control-socket
requests. LuCI ACLs should separate read-only monitoring from administrative
actions.

### Overview

- version, uptime, and configured dataplane;
- liveness and readiness;
- active connections and capacity utilization;
- current throughput;
- recent DNS and VLESS error rates;
- WAN and default-route state.

### Traffic

- direct, proxy, and blackhole decisions;
- userspace, raw, and sockhash bytes;
- connection rate, rejection rate, and timeouts;
- active connections by bounded protocol phase.

### DNS And FakeDNS

- query rate, latency, and SERVFAIL rate;
- resolver and outbound results;
- A and AAAA query distribution;
- FakeDNS pool occupancy and lease states;
- allocation and reverse-lookup failures.

### REALITY And Vision

- handshake duration and failure stage;
- TLS version and cipher distribution;
- `CommandDirect` eligibility separately from offload admission;
- framed and direct bytes;
- raw-reactor and kernel-offload occupancy.

### eBPF

- loaded hooks, program IDs, and JIT status;
- map occupancy and capacity;
- lookup hit, miss, and expiry;
- socket assignment failures;
- active sockhash flows by owner and fallback reasons;
- SOCKHASH aggregate bytes, packets, redirect errors, and last activity;
- persistent FakeDNS pin compatibility and restored/pruned lease counts;
- ring-buffer event loss.

### Diagnostics

- ordered route simulation for a domain and port;
- DNS query through a selected resolver and outbound;
- validated ping, traceroute, and TCP connect probes;
- BPF capability and attachment status;
- bounded recent events;
- redacted diagnostic bundle download.

The web backend must expose explicit operations only. It must not provide a
shell command field. Inputs such as hostnames, IP addresses, ports, query types,
and probe counts require strict validation and hard timeouts.

## Time Series And Retention

A Prometheus or Grafana server should not run on the router. The preferred
deployment is:

```text
router exporter -> external Prometheus or VictoriaMetrics -> Grafana
```

`prometheus-node-exporter-lua` can supply OpenWrt system metrics. A custom
xray-zig collector can query the Unix socket and render the Prometheus text
format. The endpoint should remain private to the management network or be
accessed over a protected management tunnel.

For a completely standalone router, `luci-app-statistics` and collectd can keep
a small fixed set of historical system metrics in RRD files. Its default
`/tmp/rrd` storage is in RAM and is lost on reboot. Writing frequent RRD updates
to internal flash is not recommended. Short live charts in the custom LuCI app
may keep their recent samples in browser memory without any router-side time
series database.

## Health And Alerts

Liveness should answer only whether the runtime event loop and control API are
responding. Readiness should verify local requirements without making an
external request on every check:

- configured listeners exist;
- dispatcher and raw reactor are running;
- required BPF programs, links, maps, and listener sockets are installed;
- the SOCKHASH monitor is running when offload is required;
- required FakeDNS publication path is available and configured persistent
  pins have the expected schema and configuration fingerprint;
- configured capacity is nonzero and internal state is consistent.

External DNS, TCP, and REALITY probes are separate scheduled or manual checks.

Recommended alerts include:

- process or readiness down;
- DNS SERVFAIL or timeout ratio above its baseline;
- REALITY handshake failures concentrated at one stage;
- raw-reactor, worker, DNS-query, or BPF-map utilization approaching capacity;
- FakeDNS pool exhaustion or rapid stale-lease growth;
- BPF link loss, lookup misses, socket assignment failures, or ring-buffer loss;
- Vision SOCKHASH admission failures after `CommandDirect` eligibility;
- freedom SOCKHASH fallback or hybrid rates above their established baseline;
- redirect errors or unexplained divergence between flow-close bytes and
  `xz_sh_total`;
- RSS above the configured budget;
- conntrack pressure, interface drops, or loss of the expected default route.

Thresholds should be established from field baselines rather than hard-coded
before measurements are available.

## Implementation Order

1. Add an allocation-free internal metrics registry with counters, gauges, and
   fixed histograms. Instrument the existing typed routing, DNS, Vision,
   freedom, raw-reactor, and SOCKHASH transitions at their ownership points;
   do not parse the current log text back into the process.
2. Add an immutable bounded snapshot that combines the registry with direct
   reads of the already-owned FakeDNS/SK_LOOKUP/SOCKHASH maps. Cross-check
   SOCKHASH flow-close totals against `xz_sh_total` and expose map capacities,
   not raw keys or domain metadata.
3. Add the root-controlled Unix socket plus `xray-zig ctl status`, `metrics`,
   `bpf`, and bounded `events`. Readiness must cover required BPF links,
   SOCKHASH monitor state, FakeDNS pin compatibility, and capacity invariants.
4. Convert the SK_LOOKUP and SOCKHASH field harnesses to assert the control API
   while retaining `bpftool`, log, and client-byte checks as independent test
   oracles. Add a monitoring-disabled/enabled A/B arm for CPU, throughput, RSS,
   latency, scrape size, and scrape time.
5. Add missing SK_LOOKUP counters only after the stable metrics enum exists.
   Prefer bounded per-CPU counters; add rare-event buffering only for errors.
   Do not attach TC solely for observability before a TC interface/configuration
   contract exists.
6. Package an OpenWrt system exporter and an xray-zig Prometheus collector. The
   collector queries the Unix socket and does not require BPF filesystem access.
7. Add the rpcd/ubus adapter and a read-only LuCI overview, then DNS, FakeDNS,
   REALITY/Vision, traffic, and diagnostic views. Keep administrative service,
   firewall, and firmware operations outside the monitoring API.
8. Add external Grafana dashboards and alerts only after field baselines exist.
   Vision eligibility and freedom admission must have separate denominators.
   A future UDP path must reuse the fixed `network=udp` dimension and add
   datagram, idle-expiry, and error accounting only after its kernel capability
   and bidirectional field tests pass.

## References

- [OpenWrt statistical data overview](https://openwrt.org/docs/guide-user/perf_and_log/statistical.data.overview)
- [OpenWrt luci-app-statistics](https://openwrt.org/docs/guide-user/luci/luci_app_statistics)
- [OpenWrt prometheus-node-exporter-lua](https://github.com/openwrt/packages/tree/master/utils/prometheus-node-exporter-lua)
- [OpenWrt ubus](https://openwrt.org/docs/techref/ubus)
- [rpcd ucode plugin example](https://github.com/openwrt/rpcd/blob/master/examples/ucode/example-plugin.uc)
- [Prometheus instrumentation practices](https://prometheus.io/docs/practices/instrumentation/)
- [Prometheus metric naming](https://prometheus.io/docs/practices/naming/)
- [Prometheus exposition formats](https://prometheus.io/docs/instrumenting/exposition_formats/)
