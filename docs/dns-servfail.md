# DNS SERVFAIL Under Concurrent Load

## Failure Symptoms

Proxy-routed TCP connections worked, but browser behavior was unstable and
Firefox reported `NS_ERROR_OFFLINE`. A test client showed a resolver split:

- `google.com` returned `SERVFAIL` through the local system resolver.
- `ya.ru` returned its expected A and AAAA records.
- Switching the DNS path back to Go Xray immediately restored `google.com` resolution.

The result follows the configured resolver rules. Yandex domains select
`77.88.8.8`; unmatched domains such as Google select the final `8.8.8.8` rule.
This was a separate resolver defect. Later isolation showed that the
endpoint-specific WSS reconnect failure itself was caused by IPv6 transparent
original-destination recovery; see `ipv6-original-destination.md`.

## Reproduction

The Zig DNS inbound could reproduce the split without changing NAT:
queries for several catch-all-resolver domains succeeded, while `example.com`
returned `SERVFAIL`. The test network showed the same peculiarity:
some direct UDP DNS queries time out even though DNS over TCP succeeds.

The current deterministic regression test is:

```sh
zig build e2e-dns -Doptimize=ReleaseFast
```

`tests/e2e/dns-fallback.py` retains its historical filename, but now verifies
the final outbound policy. It sends 32 requests concurrently through xray-zig
and requires every resolver request to arrive over TCP through the selected
outbound. The test fails if the upstream receives any UDP packet, if a query is
lost, or if bounded concurrency stalls the batch.

## Root Cause

Two behaviors combined into a resolver-wide outage:

1. The DNS inbound sent selected upstream queries directly over UDP. This field
   path selectively loses requests to the catch-all resolver.
2. The inbound receive loop handled one DNS packet synchronously. One five-second
   upstream timeout prevented every queued LAN DNS request from being read.

Browsers issue several DNS requests in parallel. A single lost request therefore
blocked unrelated names long enough for the local resolver and browser to mark
the network offline.

## Initial Availability Fix (Superseded)

- DNS packets run as independent tasks, bounded to 16 in-flight queries.
- Each task owns a fixed 4 KiB packet value; packet memory is bounded to 64 KiB
  and does not allocate from the process-lifetime arena.
- Upstream UDP gets 300 ms to respond, then the same query retries over framed
  DNS-over-TCP.
- A UDP response with the DNS truncation bit also retries over TCP.
- If both transports fail, the warning includes the queried domain, selected
  resolver, and final error before returning `SERVFAIL`.

## Final Outbound Policy

The direct UDP/TCP retry was superseded because proxy-domain DNS must follow the
configured outbound policy and direct public DoH can be blocked.

- Every DNS rule now requires `outboundTag` as well as `resolver`.
- Resolver requests are framed as DNS-over-TCP and dispatched through that
  outbound.
- Direct-domain rules can select a resolver through `direct`.
- The final `domains: ["domain:"]` catch-all can use a resolver through the
  VLESS/REALITY `proxy` outbound.
- Proxied resolver traffic follows the REALITY connection rather than making a
  direct DNS or DoH connection.

## Validation

- Before outbound-routed DNS replaced direct resolver access, 32 forced UDP
  drops completed through TCP fallback in 0.608 seconds and 64 completed in
  four bounded waves in 1.208 seconds.
- ReleaseFast unit tests passed.
- The local real-Xray normal REALITY and Vision traffic probes passed.
- A real-server syscall trace resolved Google and Cloudflare A/AAAA records with
  three connections to the proxy server and zero direct resolver connections.
- The outbound-routed harness completed 32 concurrent TCP DNS queries in 0.048
  seconds with no upstream UDP packets.
