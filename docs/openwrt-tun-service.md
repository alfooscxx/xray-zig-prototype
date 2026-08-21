# OpenWrt TUN Service

The GL-MT6000 deployment uses the `procd` definitions in
`contrib/openwrt/`. The service starts xray-zig with a 768 MiB sizing budget,
896 workers, and 1,500 raw-reactor slots. This leaves enough executor headroom
for a TUN configuration with `maxConnections` set to 256, since each active
TUN flow can occupy three concurrent tasks. The wrapper waits for `xray0`,
installs live-only policy routing and nftables rules, and removes only its own
state when stopped. It does not modify UCI or any file in `/etc/config`.

Install an AArch64 `cortex_a53` ReleaseFast binary and a native config that
contains both the `xray0` TUN inbound and any optional SOCKS inbound:

```sh
install -m 0755 xray-zig /usr/bin/xray-zig
install -m 0755 contrib/openwrt/xray-zig-service /usr/libexec/xray-zig-service
install -m 0755 contrib/openwrt/xray-zig-prometheus-collector /usr/libexec/xray-zig-prometheus-collector
install -m 0755 contrib/openwrt/xray-zig.init /etc/init.d/xray-zig
install -m 0600 xray-zig.json /etc/xray-zig/xray-zig.json
/etc/init.d/xray-zig enable
/etc/init.d/xray-zig start
```

The service creates the root-only `/run/xray-zig/control.sock`. Read status or
the bounded Prometheus snapshot locally with:

```sh
xray-zig ctl status
/usr/libexec/xray-zig-prometheus-collector
```

The collector only reads the control socket; it does not open bpffs or locate
BPF objects by name. An external exporter should invoke it at a 15- or
30-second interval and keep the resulting endpoint on the management network.

The live nftables chain considers only TCP arriving from `br-lan`. UDP stays
on the ordinary router path because the runtime does not yet wire UDP into the
TUN inbound. Local destinations, `127.0.0.0/8`, `::1/128`, all of
`192.168.0.0/16`, and IPv6 link-local destinations return before the TCP mark.
The mark selects policy table 100, whose IPv4 and IPv6 defaults point to
`xray0`. A single named rule in the existing fw4 forward chain admits marked
LAN-to-TUN packets.

The wrapper owns table `inet xray_zig_tun`, fwmark `0x7872/0xffff`, rule
priority 10072, and the two default routes it installs in policy table 100.
Confirm these identifiers are unused before deploying to a different router.
The wrapper removes stale instances before every start and recreates them
after a `procd` respawn. A normal stop or restart also deletes them.

Validate live state with:

```sh
ubus call service list '{"name":"xray-zig"}'
ip rule list
ip -6 rule list
ip route show table 100
ip -6 route show table 100
nft list table inet xray_zig_tun
nft -a list chain inet fw4 forward
```
