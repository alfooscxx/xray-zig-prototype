# TUN UDP foundation

This branch deliberately keeps UDP code separate from the experimental TCP
stack. It does not wire UDP into the runtime or change the configuration
schema. The integration commit can therefore merge TCP and UDP work without
both branches editing `src/proxy/tun/inbound.zig`, `src/proxy/tun/packet.zig`,
or `src/core/mod.zig`.

## Modules and ownership

- `src/proxy/tun/udp_packet.zig` parses and builds complete IPv4/IPv6 UDP
  packets. IPv4 accepts a zero UDP checksum and validates every nonzero one.
  IPv6 requires and validates a UDP checksum. IP fragments and IPv6 extension
  headers are rejected rather than silently misparsed.
- `src/net/datagram.zig` defines the protocol-independent datagram session,
  response sink, dispatcher, and close notification.
- `src/proxy/tun/udp.zig` owns a bounded five-tuple flow registry. A stable
  `flow_id` lets an outbound retain a direct UDP socket or proxy stream. The
  caller supplies monotonic nanoseconds, which makes idle expiry deterministic
  and testable. Expiry, dispatch failure, and shutdown notify the outbound.
- `src/proxy/freedom/udp.zig` provides a direct association backed by one
  kernel UDP socket, preserving the source port for the life of the flow. Its
  dispatcher adapter is synchronous and waits for at most one response; the
  association API is intended for the eventual asynchronous receive pump.
- `src/proxy/vless/udp.zig` contains the confirmed classic VLESS UDP request
  header and two-byte big-endian datagram framing codec.

`datagram.ResponseSink` is borrowed and valid only during `dispatch`. This
keeps packet buffers stack-owned and makes ownership explicit. `udp.Handler`
and each concrete dispatcher are single-owner objects in the current
foundation. Calls belonging to one `flow_id` must be serialized. Before the
runtime processes different flows in parallel, it must either shard ownership
by flow or add synchronization around the registries.

## Runtime integration contract

The shared TUN reader should first inspect the IP protocol. TCP packets remain
owned by the TCP flow manager. UDP packets are passed unchanged to
`udp.Handler.handlePacket`, together with:

1. the inbound tag and selected outbound tag;
2. a monotonic timestamp in nanoseconds;
3. a `PacketSink` that serializes writes to the TUN device.

The datagram runtime dispatcher selects an outbound using the same ordered
routing rules as TCP, but invokes the separate datagram contract. A production
implementation should give every active flow a receive pump. That pump calls
`freedom.udp.Association.receive` or reads the next VLESS frame and emits every
response through the TUN packet sink. The current synchronous direct adapter
is suitable for DNS and first integration tests, but is not the final pump:
unsolicited responses and multiple replies must not wait for a later uplink
packet.

DNS is an ordinary UDP association. This layer performs no port-53 hijacking
and requires no firewall changes.

## VLESS boundary

The implementation follows the upstream Xray-core sources:

- VLESS request encoding accepts `RequestCommandUDP` and writes the normal
  port-then-address target:
  <https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/encoding.go>
- `EncodeBodyAddons` selects `MultiLengthPacketWriter` for UDP. It prefixes
  each datagram with a two-byte big-endian length; `LengthPacketReader`
  reconstructs that boundary:
  <https://github.com/XTLS/Xray-core/blob/main/proxy/vless/encoding/addons.go>
- Current Xray-core rejects direct UDP for the `xtls-rprx-vision` inbound flow,
  while its outbound converts Vision UDP to XUDP over the VLESS Mux command:
  <https://github.com/XTLS/Xray-core/blob/main/proxy/vless/inbound/inbound.go>
  and
  <https://github.com/XTLS/Xray-core/blob/main/proxy/vless/outbound/outbound.go>.

Consequently the codec rejects every nonempty VLESS flow. A real UDP proxy
path for the project's current REALITY plus Vision configuration requires an
XUDP/Mux implementation, or a separately configured VLESS user with empty
flow. Sending classic command `0x02` with the Vision addon would be a known
protocol error, not a partial implementation.

## Still required for end-to-end UDP

- Add UDP fields to the TUN configuration and validate flow capacity and idle
  timeout in the common config layer.
- Route datagram sessions in `src/core/mod.zig` and expose freedom/VLESS
  datagram dispatchers.
- Add asynchronous per-flow receive pumps and safe synchronization between
  packet arrival, idle expiry, and outbound teardown.
- Reuse the existing REALITY connection setup for a VLESS datagram transport.
- Implement and test XUDP/Mux before enabling UDP on a Vision account.
- Add ICMP unreachable/Packet Too Big handling, PMTU policy, and tests on the
  real router. IPv4 and IPv6 fragmentation remain intentionally unsupported.

No firewall, boot script, or remote-router operation is part of this module.
