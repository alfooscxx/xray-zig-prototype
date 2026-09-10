# SOCKHASH Download Backlog

## Reproduction (2026-09-09)

Firefox reported `NS_ERROR_NET_PARTIAL_TRANSFER` after HTTP 200 from
`release-assets.githubusercontent.com` while downloading a WSL release.
The active AArch64 GL-MT6000 reproduced the failure with curl, independently
of Firefox. Its running kernel was Linux 6.12.94 with `CONFIG_HZ=100` and
`CONFIG_INET_DIAG` disabled. The active transparent path used SK_LOOKUP and
Vision SOCKHASH, despite the control status identifying the deployment as TUN.

The test object was `wsl.2.7.13.0.x64.msi` from Microsoft/WSL release 2.7.13.
All transfer bodies were discarded locally rather than stored on the router.

| Path | Request | Result |
| --- | --- | --- |
| Transparent SOCKHASH, initial probe | First 32 MiB | Reset after 5,190,681 HTTP body bytes |
| Router SOCKS / raw reactor | First 32 MiB | All 33,554,432 bytes received |
| Router SOCKS / raw reactor | Complete MSI | HTTP 200, 258,985,984 bytes in 15.986 s |
| Transparent SOCKHASH, 5 ms sampler | First 32 MiB | Reset after 1,881,113 bytes |
| Transparent SOCKHASH, 2 ms sampler | First 32 MiB | Reset after 3,756,480 bytes |

## Measurements

A temporary native sampler opened the running process with `pidfd_open`,
briefly duplicated selected socket FDs with `pidfd_getfd`, read `TCP_INFO`,
`SIOCOUTQ`, `FIONREAD`, and socket memory parameters, and immediately closed
each duplicate. It never read payload, changed socket options, or retained
socket duplicates between samples. BPF maps were opened read-only by IDs
confirmed in the production process's fdinfo; names and value sizes were
validated. SO_COOKIE and `xz_sh_peers` associated the two directions with the
test's fixed client source-port range.

The last 2 ms sample for flow 183987 already observed two backpressure events:

| Quantity | Bytes unless stated otherwise |
| --- | ---: |
| Flow redirected bytes, both directions | 7,953,822 |
| Flow released credit | 3,772,370 |
| Outstanding redirect credit | 4,181,452 |
| Global outstanding redirect credit | 4,181,452 |
| Client TCP bytes acknowledged, including pre-offload bytes | 3,777,317 |
| Client TCP send queue (`SIOCOUTQ`) | 0 |
| Client TCP not-yet-sent bytes | 0 |
| Client advertised receive window | 442,368 |
| Client socket send-buffer limit | 640,512 |
| Client TCP total retransmissions | 0 |
| Client smoothed RTT | 2.760 ms |

The 4,947-byte offset between client TCP progress and released credit was
already present in earlier stable samples. With that pre-offload/direction
offset, released credit matched live TCP progress at the failure sample.
Thus this run did not fail because the userspace credit refresh lagged behind
actual destination progress. About 4 MiB of redirected data was still outside
the destination's ordinary TCP send queue. The backlog size is inferred from
byte conservation, not a direct walk of the kernel's SKB list.

The global credit was far below its 64 MiB limit. The next incoming SKB can
exceed the 4 MiB per-flow limit even when the last sampled credit is slightly
below that threshold. The final lifecycle log recorded
`upstream_bytes=7963567 errors=0 backpressure=6 reset=true`.

Before failure, several samples showed an empty client send queue while
megabytes remained pending in the redirect path. The client advertised a
nonzero receive window throughout those samples. TCP retransmissions were
zero throughout the sampled flow. This is evidence of delayed delivery from
the redirect backlog into TCP, rather than a permanently blocked client.

## Interpretation And Limits

The runtime keeps consuming upstream data into SOCKHASH's intermediate
backlog faster than that backlog drains into the client socket. At its
per-flow limit, the current verdict returns SK_PASS and the monitor resets
the flow. It does not implement a pause-and-resume path that propagates
destination pressure back to upstream TCP.

Linux 6.12.94's `sk_psock_backlog` schedules a retry one jiffy later after
EAGAIN; this router's jiffy is 10 ms. This is a plausible contributor to the
observed gaps with an empty destination queue. The sampler did not trace
workqueue execution, so it does not establish which wakeup or scheduling
event caused each gap. See the
[matching kernel source](https://github.com/gregkh/linux/blob/v6.12.94/net/core/skmsg.c).

The maps and socket counters were sampled sequentially, not atomically.
Small byte differences during active arrival are expected. In the 2 ms run,
median socket snapshot time was 38 microseconds; periodic FD discovery raised
the maximum to about 3 ms. The initial reproduction without a sampler also
failed, so observation did not introduce the failure itself.

Raising the limit alone does not provide flow control. A durable correction
needs bounded buffering with upstream backpressure or an ordering-safe
transfer to a path that supplies it. The SOCKS/raw-reactor path is a validated
workaround for this object. No production binary, configuration, routing,
firewall, or service state was changed during diagnosis.
