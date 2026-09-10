# FakeDNS Reconnect Failure

> Status: superseded as the primary diagnosis. Later resolver evidence
> showed `google.com` returning `SERVFAIL` while `ya.ru` succeeded during the
> same test. See `dns-servfail.md`. Making FakeDNS opt-in remains the correct
> config behavior, but it did not by itself explain the
> browser-wide instability.
> The WSS-specific root cause was later confirmed as IPv6 original-destination
> recovery; see `ipv6-original-destination.md`.

## Symptoms

During an extended transparent-routing test, most traffic worked through
xray-zig. Fresh destinations from the affected workstation,
including an external-IP check, also showed proxy routing. One existing WSS
endpoint could not reconnect from that workstation, while a second device
connected to the same domain successfully.

Four sessions logged
`response wait failed: EndOfStream`, but the old log did not distinguish a
client that abandoned the handshake from an upstream VLESS close.

## Reproduction Model

The superseded test config enabled FakeDNS. Its domain-to-address map was
process-local, while clients cached the synthetic A or AAAA result. Reconnecting
an endpoint did not necessarily perform a new DNS query. A later xray-zig
process could therefore have no mapping for that address or could assign it to
a different domain. A different device resolving the endpoint later
received current state and was unaffected.

Server-side TLS sniffing can hide this defect for a conventional ClientHello.
It cannot be relied on when SNI is unavailable or encrypted. A local stale-map
probe with an ordinary ClientHello succeeded because the real Xray server
recovered the destination from SNI, so the exact endpoint remains a
qualified diagnosis rather than a packet-capture-confirmed reproduction.

## Root Cause And Fix

FakeDNS was enabled unconditionally whenever a DNS config existed. This did not
match configurations that forward ordinary resolver answers, and made
long-lived application DNS state part of the proxy's routing contract.

FakeDNS is now opt-in through `dns.fakeDns`. Without that object, A, AAAA, and
other query types are forwarded to the first matching resolver rule.
Configurations can retain it for explicit FakeDNS use. VLESS response-wait
errors now report `ClientEndOfStream` and
`UpstreamEndOfStream` separately. Response-wait failures include the selected
target in ReleaseFast logs so field failures can be attributed without a
diagnostic rebuild.

## Validation

- ReleaseFast unit tests passed, including absent and explicit FakeDNS config.
- The real-Xray REALITY/Vision end-to-end harness passed.
- Ordinary DNS returned real A and AAAA resolver answers.
- The explicit FakeDNS fixture returned `198.18.0.1` and `fc00::`.
- AAAA FakeDNS plus IPv6 transparent redirect passed 16 clients and 1600
  fragmented WSS frames through the real server.
- Ordinary DNS plus IPv4 transparent redirect passed 16 clients and 1600
  fragmented WSS frames through the real server.

The artifact recorded here is superseded by the DNS concurrency and
outbound-routed DNS-over-TCP fix described in `dns-servfail.md`.
