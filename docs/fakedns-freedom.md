# FakeDNS Freedom Resolution Loop

## Failure

With FakeDNS enabled, VLESS connections worked while domain-routed `freedom`
connections stalled after the client sent its TLS ClientHello.

The redirect inbound correctly reverse-mapped the synthetic destination to its
domain. VLESS could carry that domain to the remote server, but `freedom` passed
it to the host resolver. When the host resolver used the local FakeDNS inbound,
it returned the same synthetic address and the direct connection never reached
the origin.

## Fix

Reverse-FakeDNS host targets selected for `freedom` now resolve A and AAAA
records through the configured DNS server rule and its `outboundTag`. Resolver
traffic therefore retains the existing DNS-over-TCP routing policy. The
synthetic destination family is retained as the preferred lookup and connection
family, with the other family available as fallback.

The normal host resolver remains unchanged when FakeDNS is disabled.

## Regression

```sh
zig build e2e-fakedns-freedom -Doptimize=ReleaseFast
```

The harness uses a `.invalid` target that the host resolver cannot resolve. A
local configured DNS server maps it to a local origin and the test verifies a
ClientHello-shaped payload and response across the `freedom` connection.
