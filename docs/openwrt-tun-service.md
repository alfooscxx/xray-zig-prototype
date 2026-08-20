# OpenWrt TUN Service

The GL-MT6000 deployment uses the `procd` definitions in
`contrib/openwrt/`. The service starts xray-zig with a 512 MiB sizing budget,
waits for `xray0`, installs live-only policy routing and nftables rules, and
removes only its own state when stopped.

Install an AArch64 `cortex_a53` ReleaseFast binary and a native config that
contains both the `xray0` TUN inbound and any optional SOCKS inbound:

```sh
install -m 0755 xray-zig /usr/bin/xray-zig
install -m 0755 contrib/openwrt/xray-zig-service /usr/libexec/xray-zig-service
install -m 0755 contrib/openwrt/xray-zig.init /etc/init.d/xray-zig
install -m 0600 xray-zig.json /etc/xray-zig/xray-zig.json
/etc/init.d/xray-zig enable
/etc/init.d/xray-zig start
```

When the same config also contains a `dns` inbound, `dns.fakeDns`, and the
`sk_lookup` inbound, the wrapper installs local routes for `198.18.0.0/15` and
`fc00::/18`. New FakeDNS TCP flows therefore use SK_LOOKUP. The TUN policy is
kept during migration so clients with real addresses cached before the DNS
cutover do not bypass the proxy.

The GL-MT6000 dnsmasq has DNS-rebind protection enabled and otherwise removes
the ULA AAAA answers produced by FakeDNS. After the BPF hook and local routes
are ready, the wrapper transactionally makes `127.0.0.1:1053` the all-domain
dnsmasq upstream and sets `rebind_protection=0`. This is safe only while that
local FakeDNS is the sole A/AAAA authority: xray-zig synthesizes every A and
AAAA answer instead of returning an upstream private address. On normal stop,
startup failure, child exit, or the explicit `cleanup` action, the wrapper
removes its exact upstream, restores `rebind_protection=1`, commits the DHCP
UCI package, and restarts dnsmasq before removing the FakeDNS routes. A config
without `dns.fakeDns` never enables this integration.

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
ip route show table local type local | grep 198.18
ip -6 route show table local type local | grep fc00
uci -q get dhcp.@dnsmasq[0].server
uci -q get dhcp.@dnsmasq[0].rebind_protection
bpftool prog show name xz_sk_lookup
```
