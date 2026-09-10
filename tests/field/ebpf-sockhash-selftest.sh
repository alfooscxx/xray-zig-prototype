#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 /absolute/path/ebpf-sockhash-selftest" >&2
    exit 2
fi

SELFTEST_BIN=$1
LAB_NS=xz-sh-selftest-$$
SELFTEST_PID=
WATCHDOG_PID=

cleanup() {
    status=$?
    trap - EXIT INT TERM HUP
    set +e
    if [ -n "$WATCHDOG_PID" ]; then
        kill "$WATCHDOG_PID" 2>/dev/null
        wait "$WATCHDOG_PID" 2>/dev/null
    fi
    if [ -n "$SELFTEST_PID" ]; then
        kill -KILL "$SELFTEST_PID" 2>/dev/null
        wait "$SELFTEST_PID" 2>/dev/null
    fi
    ip netns del "$LAB_NS" 2>/dev/null
    exit "$status"
}
trap cleanup EXIT INT TERM HUP

[ "$(uname -m)" = aarch64 ] || {
    echo "refusing to run: this selftest is restricted to the AArch64 field router" >&2
    exit 1
}
[ -x "$SELFTEST_BIN" ] || { echo "selftest is not executable: $SELFTEST_BIN" >&2; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool is required" >&2; exit 1; }
command -v ip >/dev/null || { echo "ip-full is required" >&2; exit 1; }
ip -V 2>&1 | grep -q 'iproute2' || { echo "BusyBox ip is insufficient; install ip-full" >&2; exit 1; }
ip netns list | grep -Eq "^$LAB_NS" && { echo "selftest namespace collision" >&2; exit 1; }

bpf_ids() {
    bpftool "$1" show name "$2" 2>/dev/null |
        awk '$1 ~ /^[0-9]+:$/ { sub(":", "", $1); print $1 }' |
        sort -n
}

PROG_NAMES="xz_sh_parser xz_sh_verdict"
MAP_NAMES="xz_sh_targets xz_sh_sources xz_sh_peers xz_sh_state xz_sh_stats xz_sh_total xz_sh_released xz_sh_total_rel"
before_programs=
for prog_name in $PROG_NAMES; do
    before_programs="$before_programs $prog_name:$(bpf_ids prog "$prog_name" | tr '\n' ',')"
done
before_maps=
for map_name in $MAP_NAMES; do
    before_maps="$before_maps $map_name:$(bpf_ids map "$map_name" | tr '\n' ',')"
done

ip netns add "$LAB_NS"
ip -n "$LAB_NS" link set lo up
ip netns exec "$LAB_NS" "$SELFTEST_BIN" &
SELFTEST_PID=$!
(
    sleep 30
    kill -KILL "$SELFTEST_PID" 2>/dev/null
) &
WATCHDOG_PID=$!

set +e
wait "$SELFTEST_PID"
selftest_status=$?
set -e
SELFTEST_PID=
kill "$WATCHDOG_PID" 2>/dev/null || true
wait "$WATCHDOG_PID" 2>/dev/null || true
WATCHDOG_PID=
[ "$selftest_status" -eq 0 ]

attempt=0
while :; do
    after_programs=
    for prog_name in $PROG_NAMES; do
        after_programs="$after_programs $prog_name:$(bpf_ids prog "$prog_name" | tr '\n' ',')"
    done
    after_maps=
    for map_name in $MAP_NAMES; do
        after_maps="$after_maps $map_name:$(bpf_ids map "$map_name" | tr '\n' ',')"
    done
    if [ "$after_programs" = "$before_programs" ] && [ "$after_maps" = "$before_maps" ]; then
        break
    fi
    attempt=$((attempt + 1))
    [ "$attempt" -lt 5 ] || {
        echo "BPF objects did not return to the pre-test ID set" >&2
        exit 1
    }
    sleep 1
done

echo "PASS: isolated SOCKHASH capability selftest and owned-object cleanup"
