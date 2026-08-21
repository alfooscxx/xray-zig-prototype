#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /absolute/path/xray-zig /absolute/path/ebpf-lab-peer" >&2
    exit 2
fi

XRAY_BIN=$1
PEER_BIN=$2
LAB_ID=$$
LAB_ROOT=/tmp/xz-ebpf-lab-$LAB_ID
CLIENT_NS=xz-client-$LAB_ID
ROUTER_NS=xz-router-$LAB_ID
SUFFIX=$((LAB_ID % 10000))
CLIENT_IF=xzcl$SUFFIX
ROUTER_IF=xzrt$SUFFIX
TUN_IF=xztun0
XRAY_PID=
PEER_PID=
BPF_LINK_ID=
BPF_PROG_ID=
BPF_MAP4_ID=
BPF_MAP6_ID=
BPF_LISTENERS_ID=
BPF_COUNTERS_ID=

assert_map4_entry() {
    bpftool map lookup id "$BPF_MAP4_ID" key hex c6 12 fe 01
}

assert_map6_entry() {
    bpftool map lookup id "$BPF_MAP6_ID" key hex \
        fd 00 78 72 61 79 eb 9f 00 00 00 00 00 00 00 01
}

terminate_pid() {
    pid=$1
    [ -n "$pid" ] || return
    kill "$pid" 2>/dev/null || return
    attempt=0
    while kill -0 "$pid" 2>/dev/null; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 5 ]; then
            kill -KILL "$pid" 2>/dev/null
            break
        fi
        sleep 1
    done
    wait "$pid" 2>/dev/null || true
}

run_bounded() {
    "$@" &
    cmd_pid=$!
    (
        sleep 15
        kill -KILL "$cmd_pid" 2>/dev/null
    ) &
    watchdog_pid=$!

    set +e
    wait "$cmd_pid"
    cmd_status=$?
    set -e
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    return "$cmd_status"
}

cleanup() {
    status=$?
    trap - EXIT INT TERM HUP
    set +e
    if [ -n "$XRAY_PID" ]; then
        terminate_pid "$XRAY_PID"
    fi
    if [ -n "$PEER_PID" ]; then
        terminate_pid "$PEER_PID"
    fi
    if [ "$status" -ne 0 ]; then
        echo "== isolated xray log ==" >&2
        sed -n '1,240p' "$LAB_ROOT/xray.log" >&2 2>/dev/null
        echo "== isolated peer log ==" >&2
        sed -n '1,160p' "$LAB_ROOT/peer.log" >&2 2>/dev/null
    fi
    ip netns del "$CLIENT_NS" 2>/dev/null
    ip netns del "$ROUTER_NS" 2>/dev/null
    rm -f "$LAB_ROOT/config.json" "$LAB_ROOT/xray.log" "$LAB_ROOT/peer.log"
    rmdir "$LAB_ROOT" 2>/dev/null
    exit "$status"
}
trap cleanup EXIT INT TERM HUP

[ "$(uname -m)" = aarch64 ] || {
    echo "refusing to run: this lab is restricted to the AArch64 field router" >&2
    exit 1
}
[ -x "$XRAY_BIN" ] || { echo "xray-zig is not executable: $XRAY_BIN" >&2; exit 1; }
[ -x "$PEER_BIN" ] || { echo "lab peer is not executable: $PEER_BIN" >&2; exit 1; }
[ -c /dev/net/tun ] || { echo "/dev/net/tun is unavailable" >&2; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool is required" >&2; exit 1; }
command -v ip >/dev/null || { echo "ip-full is required" >&2; exit 1; }
ip -V 2>&1 | grep -q 'iproute2' || { echo "BusyBox ip is insufficient; install ip-full" >&2; exit 1; }
ip netns list >/dev/null 2>&1 || { echo "ip netns support is required" >&2; exit 1; }
ip netns list | grep -Eq "^$CLIENT_NS|^$ROUTER_NS" && { echo "lab namespace collision" >&2; exit 1; }
if bpftool prog show name xz_sk_lookup 2>/dev/null | grep -q 'xz_sk_lookup'; then
    echo "refusing to run: BPF program name xz_sk_lookup already exists" >&2
    exit 1
fi
for map_name in xz_fake4 xz_fake6 xz_listeners xz_sk_count; do
    if bpftool map show name "$map_name" 2>/dev/null | grep -q "$map_name"; then
        echo "refusing to run: BPF map name $map_name already exists" >&2
        exit 1
    fi
done

mkdir "$LAB_ROOT"

cat >"$LAB_ROOT/config.json" <<'JSON'
{
  "inbounds": [
    {
      "tag": "ebpf-lab",
      "protocol": "sk_lookup",
      "settings": {
        "listen4": "0.0.0.0",
        "port4": 19080,
        "listen6": "::",
        "port6": 19081,
        "maxMapEntries": 64
      }
    },
    {"tag": "dns-lab", "listen": "192.0.2.1", "port": 53, "protocol": "dns"},
    {
      "tag": "tun-lab",
      "protocol": "tun",
      "settings": {"name": "xztun0", "mtu": 1500, "maxConnections": 8}
    }
  ],
  "outbounds": [
    {"tag": "resolver-out", "protocol": "freedom"},
    {"tag": "direct", "protocol": "freedom"}
  ],
  "dns": {
    "servers": [
      {"resolver": "127.0.0.1:15353", "outboundTag": "resolver-out", "domains": ["domain:"]}
    ],
    "fakeDns": {
      "ipPool": "198.18.254.0/30",
      "ipPool6": "fd00:7872:6179:eb9f::1/128",
      "ttl": 3,
      "reuseGraceSeconds": 2
    }
  },
  "routing": {"defaultOutboundTag": "direct"}
}
JSON

# Only these temporary namespaces and their veth pair are modified. No root
# route, default route, firewall, live TUN, or service process is inspected.
ip netns add "$CLIENT_NS"
ip netns add "$ROUTER_NS"
ip link add "$CLIENT_IF" type veth peer name "$ROUTER_IF"
ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip link set "$ROUTER_IF" netns "$ROUTER_NS"

ip -n "$CLIENT_NS" link set lo up
ip -n "$ROUTER_NS" link set lo up
ip -n "$CLIENT_NS" addr add 192.0.2.2/30 dev "$CLIENT_IF"
ip -n "$ROUTER_NS" addr add 192.0.2.1/30 dev "$ROUTER_IF"
ip -n "$CLIENT_NS" -6 addr add fd00:eb9f::2/64 dev "$CLIENT_IF" nodad
ip -n "$ROUTER_NS" -6 addr add fd00:eb9f::1/64 dev "$ROUTER_IF" nodad
ip -n "$CLIENT_NS" link set "$CLIENT_IF" up
ip -n "$ROUTER_NS" link set "$ROUTER_IF" up

ip -n "$ROUTER_NS" route add local 198.18.254.1/32 dev lo
ip -n "$ROUTER_NS" -6 route add local fd00:7872:6179:eb9f::1/128 dev lo
ip -n "$CLIENT_NS" route add 198.18.254.1/32 via 192.0.2.1 dev "$CLIENT_IF"
ip -n "$CLIENT_NS" -6 route add fd00:7872:6179:eb9f::1/128 via fd00:eb9f::1 dev "$CLIENT_IF"

ip netns exec "$ROUTER_NS" "$PEER_BIN" server >"$LAB_ROOT/peer.log" 2>&1 &
PEER_PID=$!
attempt=0
while ! grep -q '^READY$' "$LAB_ROOT/peer.log" 2>/dev/null; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 10 ] || { echo "lab peer did not become ready" >&2; exit 1; }
    kill -0 "$PEER_PID" 2>/dev/null || { echo "lab peer exited" >&2; exit 1; }
    sleep 1
done

ip netns exec "$ROUTER_NS" "$XRAY_BIN" run -config "$LAB_ROOT/config.json" >"$LAB_ROOT/xray.log" 2>&1 &
XRAY_PID=$!
attempt=0
while ! ip -n "$ROUTER_NS" link show "$TUN_IF" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 15 ] || { echo "isolated xray-zig did not create its TUN" >&2; exit 1; }
    kill -0 "$XRAY_PID" 2>/dev/null || { echo "isolated xray-zig exited" >&2; exit 1; }
    sleep 1
done

BPF_PROG_ID=$(bpftool prog show name xz_sk_lookup | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
BPF_MAP4_ID=$(bpftool map show name xz_fake4 | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
BPF_MAP6_ID=$(bpftool map show name xz_fake6 | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
BPF_LISTENERS_ID=$(bpftool map show name xz_listeners | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
BPF_COUNTERS_ID=$(bpftool map show name xz_sk_count | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
[ -n "$BPF_PROG_ID" ] && [ -n "$BPF_MAP4_ID" ] && [ -n "$BPF_MAP6_ID" ] && [ -n "$BPF_LISTENERS_ID" ] && [ -n "$BPF_COUNTERS_ID" ]
BPF_LINK_ID=$(bpftool link show | awk -v prog_id="$BPF_PROG_ID" '
    $0 ~ ("prog[[:space:]]+" prog_id "([[:space:]]|$)") {
        gsub(":", "", $1)
        print $1
        exit
    }
')
[ -n "$BPF_LINK_ID" ]
bpftool prog show id "$BPF_PROG_ID" | grep -q 'sk_lookup'
bpftool link show id "$BPF_LINK_ID" | grep -Eq "prog[[:space:]]+$BPF_PROG_ID([[:space:]]|$)"
bpftool map show id "$BPF_COUNTERS_ID" | grep -q 'percpu_array'
if ip -n "$ROUTER_NS" route show dev "$TUN_IF" | grep -q .; then
    echo "test TUN unexpectedly owns an IPv4 route" >&2
    exit 1
fi
if ip -n "$ROUTER_NS" -6 route show dev "$TUN_IF" | grep -q .; then
    echo "test TUN unexpectedly owns an IPv6 route" >&2
    exit 1
fi

# The exact fake address is locally routed, but it has not been published yet.
# A miss must remain on the normal socket lookup path and cannot reach the
# SK_LOOKUP listener, whose real bind port is deliberately different.
if assert_map4_entry >/dev/null 2>&1; then
    echo "IPv4 FakeDNS map unexpectedly contains the lab key before DNS" >&2
    exit 1
fi
run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" expect-connect-fail 198.18.254.1 18080

run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" client 192.0.2.1 53 echo4.lab 4 18080 ebpf-ipv4
assert_map4_entry
run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" client 192.0.2.1 53 echo6.lab 6 18080 ebpf-ipv6
assert_map6_entry

# The map entry is intentionally retained. After ttl + reuse grace, a new SYN
# for the same exact address must fail because bpf_ktime_get_ns has passed the
# published monotonic route_valid_until_ns, not because userspace removed it.
sleep 6
assert_map4_entry
run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" expect-connect-fail 198.18.254.1 18080
sleep 1
if grep -q 'accepted an address without a live FakeDNS lease' "$LAB_ROOT/xray.log"; then
    echo "expired IPv4 entry was still assigned to the SK_LOOKUP listener" >&2
    exit 1
fi

terminate_pid "$XRAY_PID"
XRAY_PID=

! ip -n "$ROUTER_NS" link show "$TUN_IF" >/dev/null 2>&1
! bpftool link show id "$BPF_LINK_ID" >/dev/null 2>&1
! bpftool prog show id "$BPF_PROG_ID" >/dev/null 2>&1
! bpftool map show id "$BPF_MAP4_ID" >/dev/null 2>&1
! bpftool map show id "$BPF_MAP6_ID" >/dev/null 2>&1
! bpftool map show id "$BPF_LISTENERS_ID" >/dev/null 2>&1
! bpftool map show id "$BPF_COUNTERS_ID" >/dev/null 2>&1
! ip netns exec "$ROUTER_NS" bpftool prog show id "$BPF_PROG_ID" >/dev/null 2>&1

echo "PASS: isolated FakeDNS -> SK_LOOKUP IPv4/IPv6, miss/expiry, TUN coexistence, and FD cleanup"
