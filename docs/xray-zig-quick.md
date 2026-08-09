# xray-zig-quick

`contrib/xray-zig-quick` is a small `wg-quick`-style controller for running
xray-zig as a transparent proxy on a Linux gateway. It starts and checks the
process, installs isolated `iptables`/`ip6tables` NAT chains, reports status,
and removes only the rules that it owns.

The helper is intentionally separate from xray-zig's strict JSON format. Its
profile contains device lifecycle and firewall settings; `Config` points to
the native xray-zig JSON file.

## Install on the router

Build and strip the MIPS artifact as described in the README, then install the
binary, helper, JSON config, and profile:

```sh
install -m 0755 zig-out-mips/bin/xray-zig /usr/bin/xray-zig
install -m 0755 contrib/xray-zig-quick /usr/bin/xray-zig-quick
mkdir -p /etc/xray-zig/quick
install -m 0600 field-config-test.json /etc/xray-zig/xray-zig.json
install -m 0600 contrib/xray-zig-quick.conf.example /etc/xray-zig/quick/router.conf
```

Edit `router.conf` so `Config`, `Binary`, and `LanInterface` match the device.
The example uses the field-tested 70 MiB, 80-worker, 240-raw-connection
capacity split and writes logs to tmpfs rather than persistent flash.

The JSON should bind its IPv4 redirect inbound to `0.0.0.0` and its IPv6
redirect inbound to `::`. A DNS inbound is optional. If `HijackDNS` is enabled,
the helper redirects LAN UDP port 53 for each address family that has a DNS
inbound. Other UDP traffic is untouched because xray-zig does not proxy UDP.

## Use

Run a non-mutating validation first, then bring the profile up:

```sh
xray-zig-quick check router
xray-zig-quick up router
xray-zig-quick status router
xray-zig-quick down router
```

A profile path can be used instead of a name. Named profiles resolve under
`/etc/xray-zig/quick`. Runtime state is kept in `/var/run/xray-zig-quick`.

`up` validates the JSON and waits for every configured inbound to report that
it is listening before adding firewall jumps. If startup or firewall setup
fails, it removes partial rules and stops the process. `down` removes the
jumps before stopping xray-zig, so new LAN connections are never redirected to
a dead listener. PID start times are recorded to avoid killing an unrelated
process after PID reuse.

Each address family gets a dedicated per-profile NAT chain. Within it, the
order is:

1. Redirect UDP DNS when a matching DNS inbound exists.
2. Return destinations hosted by the router itself when `BypassLocal = yes`.
3. Redirect all remaining TCP to the matching xray-zig redirect inbound.

This preserves direct LAN access to services such as SSH and the router web UI.
Routing decisions for redirected remote traffic still belong to xray-zig's
ordered routing rules.

## Profile keys

| Key | Required | Default | Meaning |
|---|---|---|---|
| `Config` | yes | - | Native xray-zig JSON path |
| `Binary` | no | `xray-zig` | Executable path or command |
| `LanInterface` | yes | - | One interface, or a comma/space-separated list |
| `IPv4` | no | `yes` | Install rules when an IPv4 redirect inbound exists |
| `IPv6` | no | `yes` | Install rules when an IPv6 redirect inbound exists |
| `HijackDNS` | no | `yes` | Redirect LAN UDP/53 to matching DNS inbounds |
| `BypassLocal` | no | `yes` | Exclude router-hosted TCP destinations |
| `MemoryBudgetMiB` | no | `70` | xray-zig runtime memory sizing input |
| `WorkerLimit` | no | `80` | Requested threaded worker limit |
| `RawConnectionLimit` | no | `240` | Requested raw-reactor connection limit |
| `LogFile` | no | `/var/run/xray-zig-quick/NAME.log` | Combined runtime output |

The firewall requires the `nat`, `REDIRECT`, and `addrtype` iptables modules.
Set `BypassLocal = no` only if the device lacks `addrtype`; doing so can send
connections to router-hosted TCP services through xray-zig.

The helper controls forwarded traffic arriving on `LanInterface`. It does not
install `OUTPUT` rules, which avoids recursively capturing xray-zig's own
REALITY connections.
