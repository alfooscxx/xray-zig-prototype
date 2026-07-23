# IPv6 Original-Destination Failure

## Failure Symptoms

During transparent-routing tests, IPv4 browsing generally worked but an existing WSS
stream using IPv6 could not reconnect. Disabling IPv6 completely on the
workstation made the same stream reconnect through xray-zig. The same IPv6
destination continued to work through Go Xray.

The Zig process stayed alive. Failed IPv6 connections reset immediately and
produced no VLESS or dispatch log entry, placing the failure before outbound
selection.

## Deterministic Reproduction

A temporary destination-specific IPv6 PREROUTING rule redirected one IPv6
address to a Zig IPv6 listener.

Before the fix:

```text
curl: (35) Recv failure: Connection reset by peer
HTTP 000, TLS not started, total 0.032 s
```

The identical destination through Go returned HTTP 301. The x86 Zig client also
returned HTTP 301 through the same VPS and VLESS IPv6 target encoding, proving
that the VLESS address bytes and VPS IPv6 connectivity were valid.

## Root Cause

`redirect` always tried the IPv4 `SO_ORIGINAL_DST` socket option first, then
fell back to `IP6T_SO_ORIGINAL_DST`. The tested MIPS kernel does not tolerate
that family probing on an accepted IPv6 redirected socket. Original-destination
recovery failed and the inbound closed the connection before dispatch.

Go Xray chooses `IPPROTO_IP` or `IPPROTO_IPV6` directly from the accepted
connection family. The Zig config already has separate IPv4 and IPv6 redirect
listeners, so probing is unnecessary.

## Fix

The redirect listener now derives an address-family value from its bind address
and passes it to each connection handler:

- IPv4 listeners call only `SO_ORIGINAL_DST` at `IPPROTO_IP`.
- IPv6 listeners call only `IP6T_SO_ORIGINAL_DST` at `IPPROTO_IPV6`.
- A failed lookup emits the inbound tag and error at warning level instead of
  silently resetting the client.

## Validation

The same destination-specific MIPS probe returned:

```text
HTTP 301, TLS 0.823 s, total 0.952 s
```

The temporary PREROUTING rule was removed immediately after each probe. With
IPv6 enabled on the affected workstation:

- Google, Cloudflare, and Microsoft completed IPv6 TLS requests through Zig.
- The previously failing WSS stream reconnected and remained connected.
- IPv6 redirect counters exceeded 4,500 TCP connections.
- Zig remained alive during the test.

Unit tests, the concurrent outbound-routed DNS harness, and real-Xray normal
and Vision traffic tests also passed.
