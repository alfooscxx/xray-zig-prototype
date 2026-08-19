# Experimental TCP-only TUN Inbound

The native `tun` inbound opens a real Linux TUN device and terminates TCP in
userspace before passing a stream to the normal xray-zig dispatcher. It does
not use redirect, TProxy, nftables, iptables, or a hidden loopback listener.

The minimal config is:

```json
{
  "inbounds": [
    {
      "tag": "tun-in",
      "protocol": "tun",
      "settings": {
        "name": "xray0",
        "mtu": 1500,
        "maxConnections": 128
      }
    }
  ]
}
```

`name` is required and must fit Linux's 15-byte interface-name limit. `mtu`
defaults to 1500 and currently accepts 1280 through 1500. `maxConnections`
defaults to 128 and bounds live TCP flow state. TUN inbounds do not have
`listen` or `port` fields.

The process requests `IFF_TUN | IFF_NO_PI` from `/dev/net/tun`. The device is
non-persistent: it disappears when xray-zig exits. xray-zig intentionally does
not bring the link up, assign addresses, or install routes. This keeps every
network change visible during experiments and avoids coupling runtime config to
OpenWrt firewall or boot policy.

Run field commands on the active AArch64 router through SSH as described in
`router-field-access.md`. Never send these commands to the legacy MIPS optical
bridge. For a narrow router-local IPv4 probe:

```sh
xray-zig run -config /tmp/tun.json
ip addr add 198.18.255.1/32 dev xray0
ip link set xray0 up
ip route add TEST_DESTINATION_V4/32 dev xray0
wget -4 -O /tmp/tun-result https://TEST_HOST/
ip route del TEST_DESTINATION_V4/32 dev xray0
```

IPv6 uses the same interface:

```sh
ip -6 addr add fd00:7872:6179::1/128 dev xray0
ip -6 route add TEST_DESTINATION_V6/128 dev xray0
wget -6 -O /tmp/tun-result-v6 https://TEST_HOST/
ip -6 route del TEST_DESTINATION_V6/128 dev xray0
```

Routes must not capture an outbound's own control connection. In particular, a
route that sends a destination into TUN and then selects `freedom` for the same
destination loops back into TUN. Exclude direct destinations, protect the proxy
server's route, or use external policy routing. xray-zig does not install these
policies automatically.

## Current TCP Scope

The inbound supports IPv4 and IPv6 TCP handshakes, ordered payload delivery,
window tracking, half-close/FIN, RST, TCP/IP checksums, per-family MSS, and TLS
domain sniffing from the first payload. Each flow is bridged to the existing
dispatcher with a local `AF_UNIX` socket pair.

This is an experimental compact TCP endpoint, not a complete production
netstack. It does not yet implement downlink retransmission, congestion
control, PMTU discovery, TCP SACK/timestamps, IPv4 fragmentation, or IPv6
extension headers. It is suitable for the local/router experiments documented
below, where the TUN boundary itself is lossless. Loss after packets leave the
router can still require downlink retransmission, so routed LAN deployment
needs that work before being treated as production-ready.

UDP is deliberately unsupported. UDP packets are recognized and dropped; no
UDP session is opened and no UDP Vision mode is attempted.

## GL-MT6000 Experiment

The active field router is a GL.iNet GL-MT6000 accessed only through SSH. The
legacy MIPS device is only an optical bridge and was not involved in this
experiment. The first field run used OpenWrt 25.12.5, Linux
6.12.94, and `aarch64_cortex-a53`. The router needed the matching `kmod-tun`
package before `/dev/net/tun` appeared. No firewall or boot scripts were
changed.

The tested binary was a stripped, statically linked `aarch64-linux-musl`
ReleaseFast build. A temporary `xray0` handled:

- one IPv4 HTTPS request through VLESS/REALITY/Vision;
- eight concurrent IPv4 HTTPS requests;
- a complete 1 MiB IPv4 HTTPS transfer;
- one IPv6 HTTPS request after correcting the IPv6 MSS from 1460 to 1440.

Both address families reached Vision raw handoff. Temporary host routes and
interface addresses were removed with the test process.
