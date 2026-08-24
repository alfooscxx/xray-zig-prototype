#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /absolute/path/sk-lookup-conformance" >&2
    exit 2
fi

BIN=$1
FORMAT=${FORMAT:-json}
CFG_BLOCKS=${CFG_BLOCKS:-128}
ROUTED=${ROUTED:-0}
TRANSPARENT=${TRANSPARENT:-0}
LAB_ROOT=$(mktemp -d /tmp/xz-sk-lookup-conformance.XXXXXX)
ACTIVE_NS=
ACTIVE_CLIENT_NS=
SERVER_PID=
WATCHDOG_PID=

terminate() {
    pid=$1
    [ -n "$pid" ] || return 0
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

cleanup() {
    status=$?
    trap - EXIT INT TERM HUP
    set +e
    terminate "$WATCHDOG_PID"
    terminate "$SERVER_PID"
    if [ -n "$ACTIVE_NS" ]; then
        ip netns del "$ACTIVE_NS" 2>/dev/null
    fi
    if [ -n "$ACTIVE_CLIENT_NS" ]; then
        ip netns del "$ACTIVE_CLIENT_NS" 2>/dev/null
    fi
    rm -f "$LAB_ROOT"/*.log
    rmdir "$LAB_ROOT" 2>/dev/null
    exit "$status"
}
trap cleanup EXIT INT TERM HUP

[ "$(id -u)" -eq 0 ] || { echo "root is required for isolated netns and BPF" >&2; exit 1; }
[ -x "$BIN" ] || { echo "not executable: $BIN" >&2; exit 1; }
command -v ip >/dev/null || { echo "iproute2 is required" >&2; exit 1; }
case "$FORMAT" in json|tsv) ;; *) echo "FORMAT must be json or tsv" >&2; exit 2 ;; esac
case "$CFG_BLOCKS" in *[!0-9]*|'') echo "CFG_BLOCKS must be an integer" >&2; exit 2 ;; esac
[ "$CFG_BLOCKS" -le 512 ] || { echo "CFG_BLOCKS must not exceed 512" >&2; exit 2; }
case "$ROUTED" in 0|1) ;; *) echo "ROUTED must be 0 or 1" >&2; exit 2 ;; esac
case "$TRANSPARENT" in 0|1) ;; *) echo "TRANSPARENT must be 0 or 1" >&2; exit 2 ;; esac

if [ "$FORMAT" = tsv ]; then
    printf 'case\tconnect_result\taccept_result\tbpf_sk_assign_return_counter\tbpf_sk_assign_error_counter\tctx_sk_seen\tinstruction_count\n'
fi

run_case() {
    case_name=$1
    blocks=$2
    ACTIVE_NS="xz-skc-$$-$case_name"
    ACTIVE_CLIENT_NS="xz-skcc-$$-$case_name"
    log="$LAB_ROOT/$case_name.log"
    ip netns add "$ACTIVE_NS"
    ip -n "$ACTIVE_NS" link set lo up
    if [ "$ROUTED" = 1 ]; then
        ip netns add "$ACTIVE_CLIENT_NS"
        ip link add skc-client type veth peer name skc-router
        ip link set skc-client netns "$ACTIVE_CLIENT_NS"
        ip link set skc-router netns "$ACTIVE_NS"
        ip -n "$ACTIVE_CLIENT_NS" link set lo up
        ip -n "$ACTIVE_CLIENT_NS" addr add 192.0.2.2/30 dev skc-client
        ip -n "$ACTIVE_NS" addr add 192.0.2.1/30 dev skc-router
        ip -n "$ACTIVE_CLIENT_NS" link set skc-client up
        ip -n "$ACTIVE_NS" link set skc-router up
        ip -n "$ACTIVE_CLIENT_NS" route add 198.51.100.1/32 via 192.0.2.1 dev skc-client
        ip -n "$ACTIVE_NS" route add table 100 local 0.0.0.0/0 dev lo
        ip -n "$ACTIVE_NS" rule add priority 100 iif skc-router lookup 100
    else
        ip -n "$ACTIVE_NS" addr add 198.51.100.1/32 dev lo
    fi

    ip netns exec "$ACTIVE_NS" "$BIN" server "$case_name" "$blocks" "$FORMAT" "$TRANSPARENT" >"$log" 2>&1 &
    SERVER_PID=$!
    attempt=0
    while ! grep -q '^READY$' "$log" 2>/dev/null; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 20 ] || { sed -n '1,160p' "$log" >&2; return 1; }
        kill -0 "$SERVER_PID" 2>/dev/null || { sed -n '1,160p' "$log" >&2; return 1; }
        sleep 1
    done

    (
        sleep 10
        kill -KILL "$SERVER_PID" 2>/dev/null || true
    ) &
    WATCHDOG_PID=$!
    if [ "$ROUTED" = 1 ]; then
        ip netns exec "$ACTIVE_CLIENT_NS" "$BIN" client 198.51.100.1
    else
        ip netns exec "$ACTIVE_NS" "$BIN" client 198.51.100.1
    fi
    wait "$SERVER_PID"
    SERVER_PID=
    terminate "$WATCHDOG_PID"
    WATCHDOG_PID=
    sed -n '/^{/p; /^[a-z_][a-z_]*	/p' "$log"
    ip netns del "$ACTIVE_NS"
    ACTIVE_NS=
    if [ "$ROUTED" = 1 ]; then
        ip netns del "$ACTIVE_CLIENT_NS"
    fi
    ACTIVE_CLIENT_NS=
}

run_case direct 0
run_case chain 0
run_case tail_call 0
run_case cfg_load "$CFG_BLOCKS"
