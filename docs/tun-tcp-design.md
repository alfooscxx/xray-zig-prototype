# TUN TCP State Engine

The TCP side of the TUN inbound is split into two layers. `inbound.zig` owns the
single TUN reader, flow map, dispatcher bridge, and one protocol-owned
`io_uring` data-plane reactor.
`tcp.zig` is a deterministic state engine. It has no allocator, socket, or
clock dependency; callers supply monotonic milliseconds and turn returned
segments into TUN writes. This keeps a future UDP demultiplexer from needing a
second reader for the same interface.

Each flow has a fixed 32-segment downlink retransmission queue. Every slot can
hold one maximum-MTU TCP payload, so memory is bounded independently of peer
behavior. The engine limits new data by the smaller of the advertised receive
window and a basic congestion window. A cumulative ACK releases slots and
wakes blocked bridge writers. Partial ACKs trim the first queued segment.
Advertised-window updates use TCP sequence and acknowledgment freshness, so a
reordered or invalid ACK cannot overwrite a newer window and stall downlink
traffic.

The oldest unacknowledged SYN-ACK, data segment, or FIN is retransmitted after
the RTO. The initial RTO is 300 ms, doubles to an 8-second ceiling, and gives
up after eight retries. Three eligible duplicate ACKs trigger a fast
retransmit. Timeout and fast retransmit reduce the congestion window. Half-open
flows expire after 20 seconds and otherwise-idle flows after five minutes, so
neither state nor dispatcher work can remain live forever without traffic.

The flow owner waits for enough client payload to sniff and route, creates an
`AF_UNIX` bridge, starts one temporary dispatcher task, and hands the other end
to the reactor. The owner then exits. The reactor submits at most one receive
and one send operation per bridge and uses an `eventfd` for TUN-reader handoff.
Its one 50 ms monotonic `io_uring` timeout drives every flow's retransmission
and idle expiry. After the outbound reaches Vision raw handoff, both sides of
the userspace bridge are reactor-owned and the established TUN flow holds no
per-flow executor worker.

The uplink queue and reactor buffer are bounded. A full bridge buffer stops the
reactor from consuming TUN segments, so their payload is not acknowledged and
normal TCP retransmission supplies backpressure. Downlink reads stop while
buffered bytes are waiting for the peer window or congestion window. CQEs are
canceled and the ring is closed before flow storage is released; kernel I/O
never retains a pointer into a destroyed flow.

Sequence comparisons use wrapping 32-bit arithmetic. Ordered uplink payload is
accepted immediately. A retransmit overlapping the current receive sequence is
trimmed so only new bytes reach the dispatcher. Future out-of-order data is not
buffered: the current cumulative ACK is sent and the client must retransmit the
gap. This bounds receive-side memory while retaining correct delivery.

The packet layer advertises an MSS derived from the configured TUN MTU for both
IPv4 and IPv6. Downlink segmentation also honors the smaller of this value and
the MSS in the client's SYN.

## Remaining limitations

This is still a compact endpoint rather than a complete general-purpose TCP
stack:

- no selective acknowledgments or out-of-order receive reassembly;
- no TCP window scaling, timestamps, Nagle algorithm, delayed ACK, or ECN;
- no RTT estimator; RTO starts from a fixed value rather than measured RTT;
- congestion control is deliberately basic and does not implement a named RFC
  algorithm completely;
- no persist timer for a peer that advertises a zero window and never sends a
  window update;
- no PMTU discovery, IP fragmentation/reassembly, ICMP error processing, or
  IPv6 extension headers;
- no TIME-WAIT table for rejecting delayed packets after flow destruction;
- no SYN cookies and no simultaneous-open support.

UDP remains outside this engine and is not handled by any of its state or
timers.
