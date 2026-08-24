#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /absolute/path/xray-zig /absolute/path/ebpf-lab-peer" >&2
    exit 2
fi

XRAY_BIN=$1
PEER_BIN=$2
LAB_ID=$$
LAB_ROOT=/tmp/xz-literal-lab-$LAB_ID
CONTROL_SOCKET=$LAB_ROOT/control.sock
CLIENT_NS=xz-lit-client-$LAB_ID
WRONG_NS=xz-lit-wrong-$LAB_ID
ROUTER_NS=xz-lit-router-$LAB_ID
SUFFIX=$((LAB_ID % 10000))
CLIENT_IF=xlc$SUFFIX
ROUTER_IF=xlr$SUFFIX
WRONG_IF=xlw$SUFFIX
ROUTER_WRONG_IF=xlx$SUFFIX
XRAY_PID=
PEER_PID=
TCPDUMP_PID=
BASE_PROGS=
BASE_MAPS=
NEW_PROG=
NEW_PROGS=
NEW_MAPS=
FAKE4_ID=
FAKE6_ID=
COUNTERS_ID=
PROGRAM_NAMES="xz_sk_lookup xz_sk_fake xz_sk_literal xz_sh_parser xz_sh_verdict"
MAP_NAMES="xz_fake4 xz_fake6 xz_listeners xz_sk_count xz_exclude4 xz_exclude6 xz_admit xz_sk_progs xz_sh_targets xz_sh_sources xz_sh_peers xz_sh_state xz_sh_stats xz_sh_total"

named_ids() {
    kind=$1
    name=$2
    bpftool "$kind" show name "$name" 2>/dev/null | sed -n 's/^\([0-9][0-9]*\):.*/\1/p' | tr '\n' ' '
}

new_named_id() {
    kind=$1
    name=$2
    baseline=$3
    for id in $(named_ids "$kind" "$name"); do
        case " $baseline " in *" $id "*) ;; *) echo "$id"; return 0 ;; esac
    done
    return 1
}

terminate_pid() {
    pid=$1
    [ -n "$pid" ] || return
    kill "$pid" 2>/dev/null || return
    attempt=0
    while kill -0 "$pid" 2>/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 5 ] || { kill -KILL "$pid" 2>/dev/null; break; }
        sleep 1
    done
    wait "$pid" 2>/dev/null || true
}

run_bounded() {
    "$@" & command_pid=$!
    ( sleep 15; kill -KILL "$command_pid" 2>/dev/null ) & watchdog_pid=$!
    if wait "$command_pid"; then command_status=0; else command_status=$?; fi
    kill "$watchdog_pid" 2>/dev/null || true
    wait "$watchdog_pid" 2>/dev/null || true
    return "$command_status"
}

expect_client_failure() {
    tag=$1; namespace=$2; address=$3; port=$4
    if run_bounded ip netns exec "$namespace" "$PEER_BIN" direct-client "$address" "$port" "$tag" >>"$LAB_ROOT/negative.log" 2>&1; then
        echo "unexpected success: $tag $address:$port" >&2
        return 1
    fi
    echo "PASS expected failure: $tag $address:$port"
}

cleanup() {
    status=$?
    trap - EXIT INT TERM HUP
    set +e
    terminate_pid "$XRAY_PID"
    terminate_pid "$PEER_PID"
    terminate_pid "$TCPDUMP_PID"
    if [ "$status" -ne 0 ]; then
        echo "== isolated literal xray log ==" >&2
        sed -n '1,260p' "$LAB_ROOT/xray.log" >&2 2>/dev/null
        echo "== isolated literal peer log ==" >&2
        sed -n '1,160p' "$LAB_ROOT/peer.log" >&2 2>/dev/null
        echo "== isolated status ==" >&2
        sed -n '1,120p' "$LAB_ROOT/status.json" >&2 2>/dev/null
        echo "== expected-negative client errors ==" >&2
        sed -n '1,160p' "$LAB_ROOT/negative.log" >&2 2>/dev/null
        for diagnostic in fake4-published counters-before-fake4 counters-after-fake4 fake6-published counters-before-fake6 counters-after-fake6; do
            echo "== $diagnostic ==" >&2
            sed -n '1,240p' "$LAB_ROOT/$diagnostic.txt" >&2 2>/dev/null
        done
        for diagnostic in bpf-xlated clock-before-fake4 clock-after-fake4 routes-before-fake4 links-before-fake4 links-after-fake4; do
            echo "== $diagnostic ==" >&2
            sed -n '1,320p' "$LAB_ROOT/$diagnostic.txt" >&2 2>/dev/null
        done
        echo "== tcpdump-fake4 ==" >&2
        sed -n '1,240p' "$LAB_ROOT/tcpdump-fake4.txt" >&2 2>/dev/null
        echo "== tcpdump-fake6 ==" >&2
        sed -n '1,240p' "$LAB_ROOT/tcpdump-fake6.txt" >&2 2>/dev/null
    fi
    ip netns del "$CLIENT_NS" 2>/dev/null
    ip netns del "$WRONG_NS" 2>/dev/null
    ip netns del "$ROUTER_NS" 2>/dev/null
    rm -f "$LAB_ROOT/config.json" "$LAB_ROOT/xray.log" "$LAB_ROOT/peer.log" "$LAB_ROOT/status.json" "$LAB_ROOT/negative.log" "$CONTROL_SOCKET" "$LAB_ROOT"/*.txt
    rmdir "$LAB_ROOT" 2>/dev/null
    exit "$status"
}
trap cleanup EXIT INT TERM HUP

[ "$(uname -m)" = aarch64 ] || { echo "refusing to run outside the AArch64 field router" >&2; exit 1; }
[ -x "$XRAY_BIN" ] || { echo "xray-zig is not executable" >&2; exit 1; }
[ -x "$PEER_BIN" ] || { echo "ebpf-lab-peer is not executable" >&2; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool is required" >&2; exit 1; }
command -v tcpdump >/dev/null || { echo "tcpdump is required" >&2; exit 1; }
command -v ip >/dev/null || { echo "ip-full is required" >&2; exit 1; }
ip -V 2>&1 | grep -q iproute2 || { echo "BusyBox ip is insufficient" >&2; exit 1; }

for name in $PROGRAM_NAMES; do
    ids=$(named_ids prog "$name")
    BASE_PROGS="$BASE_PROGS $name:$ids;"
done
for name in $MAP_NAMES; do
    ids=$(named_ids map "$name")
    BASE_MAPS="$BASE_MAPS $name:$ids;"
done

mkdir "$LAB_ROOT"
cat >"$LAB_ROOT/config.json" <<JSON
{
  "inbounds": [{
    "tag": "literal-lab", "protocol": "sk_lookup",
    "settings": {
      "listen4": "0.0.0.0", "port4": 19080,
      "listen6": "::", "port6": 19081,
      "maxMapEntries": 64,
      "sockhashOffload": {"mode":"required","maxFlows":64,"idleTimeoutSeconds":30},
      "transparentIntercept": {
        "ingressInterface": "$ROUTER_IF",
        "excludedIPs": ["192.0.2.0/29", "fd00:eb9f::/64", "203.0.113.128/25", "2001:db8:100:1::/64", "127.0.0.0/8", "::1/128", "fe80::/10"],
        "proxyServerIPs": ["203.0.113.254", "2001:db8:100::fe"]
      }
    }
  }, {"tag":"dns-lab","listen":"192.0.2.1","port":53,"protocol":"dns"}],
  "outbounds": [{"tag":"direct","protocol":"freedom"},{"tag":"dns-direct","protocol":"freedom"},{"tag":"proxy","protocol":"blackhole"}],
  "dns": {
    "servers": [{"resolver":"127.0.0.1:15353","outboundTag":"dns-direct","domains":["domain:"]}],
    "fakeDns": {"ipPool":"198.18.254.0/30","ipPool6":"fd00:7872:6179:eb9f::1/128","ttl":60,"reuseGraceSeconds":2}
  },
  "routing": {
    "rules": [
      {"domain":["domain:echo4.lab","domain:echo6.lab"],"outboundTag":"direct"},
      {"inboundTag":"literal-lab","ip":["203.0.113.10/32","2001:db8:100::10/128"],"outboundTag":"direct"}
    ],
    "defaultOutboundTag":"proxy"
  }
}
JSON

ip netns add "$CLIENT_NS"
ip netns add "$WRONG_NS"
ip netns add "$ROUTER_NS"
ip link add "$CLIENT_IF" type veth peer name "$ROUTER_IF"
ip link add "$WRONG_IF" type veth peer name "$ROUTER_WRONG_IF"
ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip link set "$ROUTER_IF" netns "$ROUTER_NS"
ip link set "$WRONG_IF" netns "$WRONG_NS"
ip link set "$ROUTER_WRONG_IF" netns "$ROUTER_NS"
for ns in "$CLIENT_NS" "$WRONG_NS" "$ROUTER_NS"; do ip -n "$ns" link set lo up; done
ip -n "$CLIENT_NS" addr add 192.0.2.2/30 dev "$CLIENT_IF"
ip -n "$ROUTER_NS" addr add 192.0.2.1/30 dev "$ROUTER_IF"
ip -n "$WRONG_NS" addr add 192.0.2.6/30 dev "$WRONG_IF"
ip -n "$ROUTER_NS" addr add 192.0.2.5/30 dev "$ROUTER_WRONG_IF"
ip -n "$CLIENT_NS" -6 addr add fd00:eb9f::2/64 dev "$CLIENT_IF" nodad
ip -n "$ROUTER_NS" -6 addr add fd00:eb9f::1/64 dev "$ROUTER_IF" nodad
ip -n "$WRONG_NS" -6 addr add fd00:eb9f:1::2/64 dev "$WRONG_IF" nodad
ip -n "$ROUTER_NS" -6 addr add fd00:eb9f:1::1/64 dev "$ROUTER_WRONG_IF" nodad
ip -n "$ROUTER_NS" addr add 203.0.113.10/32 dev lo
ip -n "$ROUTER_NS" -6 addr add 2001:db8:100::10/128 dev lo nodad
for pair in "$CLIENT_NS:$CLIENT_IF" "$WRONG_NS:$WRONG_IF" "$ROUTER_NS:$ROUTER_IF" "$ROUTER_NS:$ROUTER_WRONG_IF"; do
    ns=${pair%%:*}; interface=${pair#*:}; ip -n "$ns" link set "$interface" up
done

ip -n "$CLIENT_NS" route add 203.0.113.0/24 via 192.0.2.1 dev "$CLIENT_IF"
ip -n "$CLIENT_NS" route add 198.18.254.0/30 via 192.0.2.1 dev "$CLIENT_IF"
ip -n "$CLIENT_NS" -6 route add 2001:db8:100::/64 via fd00:eb9f::1 dev "$CLIENT_IF"
ip -n "$CLIENT_NS" -6 route add fd00:7872:6179:eb9f::1/128 via fd00:eb9f::1 dev "$CLIENT_IF"
ip -n "$WRONG_NS" route add 203.0.113.0/24 via 192.0.2.5 dev "$WRONG_IF"
ip -n "$WRONG_NS" -6 route add 2001:db8:100::/64 via fd00:eb9f:1::1 dev "$WRONG_IF"
ip -n "$ROUTER_NS" route add table 100 local 0.0.0.0/0 dev lo
ip -n "$ROUTER_NS" -6 route add table 100 local ::/0 dev lo
ip -n "$ROUTER_NS" rule add priority 100 iif "$ROUTER_IF" lookup 100
ip -n "$ROUTER_NS" -6 rule add priority 100 iif "$ROUTER_IF" lookup 100

ip netns exec "$ROUTER_NS" "$PEER_BIN" server-literals >"$LAB_ROOT/peer.log" 2>&1 & PEER_PID=$!
attempt=0
until grep -q '^READY$' "$LAB_ROOT/peer.log" 2>/dev/null; do
    attempt=$((attempt + 1)); [ "$attempt" -lt 10 ] || { echo "peer startup timeout" >&2; exit 1; }; sleep 1
done
ip netns exec "$ROUTER_NS" env XRAY_ZIG_CONTROL_SOCKET="$CONTROL_SOCKET" \
    "$XRAY_BIN" run -config "$LAB_ROOT/config.json" >"$LAB_ROOT/xray.log" 2>&1 & XRAY_PID=$!
attempt=0
until [ -S "$CONTROL_SOCKET" ]; do
    attempt=$((attempt + 1)); [ "$attempt" -lt 20 ] || { echo "xray control socket startup timeout" >&2; exit 1; }; kill -0 "$XRAY_PID"; sleep 1
done
attempt=0
until "$XRAY_BIN" ctl status --socket "$CONTROL_SOCKET" >"$LAB_ROOT/status.json" 2>/dev/null && grep -q '"ready":true' "$LAB_ROOT/status.json"; do
    attempt=$((attempt + 1)); [ "$attempt" -lt 20 ] || { echo "xray readiness timeout" >&2; exit 1; }; kill -0 "$XRAY_PID"; sleep 1
done
grep -q 'sk_lookup inbound literal-lab attached' "$LAB_ROOT/xray.log"

baseline=$(printf '%s' "$BASE_PROGS" | sed -n 's/.* xz_sk_lookup:\([^;]*\);.*/\1/p')
NEW_PROG=$(new_named_id prog xz_sk_lookup "$baseline")
[ -n "$NEW_PROG" ]
bpftool prog show id "$NEW_PROG" | grep -q sk_lookup
bpftool prog dump xlated id "$NEW_PROG" >"$LAB_ROOT/bpf-xlated.txt"
fake_baseline=$(printf '%s' "$BASE_PROGS" | sed -n 's/.* xz_sk_fake:\([^;]*\);.*/\1/p')
fake_program=$(new_named_id prog xz_sk_fake "$fake_baseline")
literal_baseline=$(printf '%s' "$BASE_PROGS" | sed -n 's/.* xz_sk_literal:\([^;]*\);.*/\1/p')
literal_program=$(new_named_id prog xz_sk_literal "$literal_baseline")
[ -n "$fake_program" ]
[ -n "$literal_program" ]
bpftool prog dump xlated id "$fake_program" >"$LAB_ROOT/bpf-fake-xlated.txt"
bpftool prog dump xlated id "$literal_program" >"$LAB_ROOT/bpf-literal-xlated.txt"
for name in $PROGRAM_NAMES; do
    baseline=$(printf '%s' "$BASE_PROGS" | sed -n "s/.* $name:\([^;]*\);.*/\1/p")
    id=$(new_named_id prog "$name" "$baseline")
    [ -n "$id" ]
    NEW_PROGS="$NEW_PROGS $id"
done
for name in $MAP_NAMES; do
    baseline=$(printf '%s' "$BASE_MAPS" | sed -n "s/.* $name:\([^;]*\);.*/\1/p")
    id=$(new_named_id map "$name" "$baseline")
    [ -n "$id" ]
    NEW_MAPS="$NEW_MAPS $id"
    case "$name" in
        xz_fake4) FAKE4_ID=$id ;;
        xz_fake6) FAKE6_ID=$id ;;
        xz_sk_count) COUNTERS_ID=$id ;;
    esac
done
[ -n "$FAKE4_ID" ] && [ -n "$FAKE6_ID" ] && [ -n "$COUNTERS_ID" ]

# The first dataplane action is DNS publication followed immediately by the
# live FakeDNS connection. No miss, literal, exclusion, or SOCKHASH flow has
# run yet, so this detects startup/order interference independently.
run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" resolve-only 192.0.2.1 53 echo4.lab 4 18080
bpftool map lookup id "$FAKE4_ID" key hex c6 12 fe 01 >"$LAB_ROOT/fake4-published.txt"
bpftool map dump id "$COUNTERS_ID" >"$LAB_ROOT/counters-before-fake4.txt"
{
    date +%s
    sed -n '1p' /proc/uptime
    ip netns exec "$ROUTER_NS" sh -c 'sed -n "1p" /proc/uptime'
} >"$LAB_ROOT/clock-before-fake4.txt"
{
    ip -n "$CLIENT_NS" route get 198.18.254.1
    ip -n "$ROUTER_NS" rule show
    ip -n "$ROUTER_NS" route show table 100
    ip -n "$ROUTER_NS" route get 198.18.254.1 from 192.0.2.2 iif "$ROUTER_IF"
} >"$LAB_ROOT/routes-before-fake4.txt" 2>&1
{
    ip -n "$CLIENT_NS" -s link show "$CLIENT_IF"
    ip -n "$ROUTER_NS" -s link show "$ROUTER_IF"
} >"$LAB_ROOT/links-before-fake4.txt"
ip netns exec "$ROUTER_NS" tcpdump -i "$ROUTER_IF" -nn -tttt -vvv -l -c 20 \
    'tcp and host 198.18.254.1 and port 18080' >"$LAB_ROOT/tcpdump-fake4.txt" 2>&1 &
TCPDUMP_PID=$!
sleep 1
set +e
run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" direct-client 198.18.254.1 18080 fake-v4-live
fake_status=$?
set -e
terminate_pid "$TCPDUMP_PID"
TCPDUMP_PID=
bpftool map dump id "$COUNTERS_ID" >"$LAB_ROOT/counters-after-fake4.txt"
{
    date +%s
    sed -n '1p' /proc/uptime
    ip netns exec "$ROUTER_NS" sh -c 'sed -n "1p" /proc/uptime'
} >"$LAB_ROOT/clock-after-fake4.txt"
{
    ip -n "$CLIENT_NS" -s link show "$CLIENT_IF"
    ip -n "$ROUTER_NS" -s link show "$ROUTER_IF"
} >"$LAB_ROOT/links-after-fake4.txt"
[ "$fake_status" -eq 0 ] || { echo "live FakeDNS v4 connection failed" >&2; exit "$fake_status"; }
run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" resolve-only 192.0.2.1 53 echo6.lab 6 18080
bpftool map lookup id "$FAKE6_ID" key hex fd 00 78 72 61 79 eb 9f 00 00 00 00 00 00 00 01 >"$LAB_ROOT/fake6-published.txt"
bpftool map dump id "$COUNTERS_ID" >"$LAB_ROOT/counters-before-fake6.txt"
ip netns exec "$ROUTER_NS" tcpdump -i "$ROUTER_IF" -nn -tttt -vvv -l -c 20 \
    'tcp and host fd00:7872:6179:eb9f::1 and port 18080' >"$LAB_ROOT/tcpdump-fake6.txt" 2>&1 &
TCPDUMP_PID=$!
sleep 1
set +e
run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" direct-client fd00:7872:6179:eb9f::1 18080 fake-v6-live
fake_status=$?
set -e
terminate_pid "$TCPDUMP_PID"
TCPDUMP_PID=
bpftool map dump id "$COUNTERS_ID" >"$LAB_ROOT/counters-after-fake6.txt"
[ "$fake_status" -eq 0 ] || { echo "live FakeDNS v6 connection failed" >&2; exit "$fake_status"; }

# Literal and negative coverage deliberately follows both live FakeDNS flows.
run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" direct-client 203.0.113.10 18080 literal-v4-direct
run_bounded ip netns exec "$CLIENT_NS" "$PEER_BIN" direct-client 2001:db8:100::10 18080 literal-v6-direct
expect_client_failure default-proxy-blackhole "$CLIENT_NS" 203.0.113.11 18080
expect_client_failure wrong-ingress "$WRONG_NS" 192.0.2.5 19080
expect_client_failure direct-listener "$CLIENT_NS" 192.0.2.1 19080
expect_client_failure excluded-cidr "$CLIENT_NS" 203.0.113.130 19080
expect_client_failure excluded-proxy4 "$CLIENT_NS" 203.0.113.254 19080
expect_client_failure excluded-proxy6 "$CLIENT_NS" 2001:db8:100::fe 19081
expect_client_failure missing-fake4 "$CLIENT_NS" 198.18.254.2 18080

grep -q 'freedom sockhash-handoff' "$LAB_ROOT/xray.log"
grep -q 'rejected an excluded literal destination' "$LAB_ROOT/xray.log"

terminate_pid "$XRAY_PID"; XRAY_PID=
for id in $NEW_PROGS; do ! bpftool prog show id "$id" >/dev/null 2>&1; done
for id in $NEW_MAPS; do ! bpftool map show id "$id" >/dev/null 2>&1; done

echo "PASS: isolated transparent literals v4/v6, ingress proof, exclusions, FakeDNS, routing, SOCKHASH, and cleanup"
