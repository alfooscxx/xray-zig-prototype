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
for prog_name in xz_sh_parser xz_sh_verdict; do
    if bpftool prog show name "$prog_name" 2>/dev/null | grep -q "$prog_name"; then
        echo "refusing to run: BPF program name $prog_name already exists" >&2
        exit 1
    fi
done
for map_name in xz_sh_targets xz_sh_sources xz_sh_peers xz_sh_state xz_sh_stats xz_sh_total; do
    if bpftool map show name "$map_name" 2>/dev/null | grep -q "$map_name"; then
        echo "refusing to run: BPF map name $map_name already exists" >&2
        exit 1
    fi
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

for prog_name in xz_sh_parser xz_sh_verdict; do
    ! bpftool prog show name "$prog_name" 2>/dev/null | grep -q "$prog_name"
done
for map_name in xz_sh_targets xz_sh_sources xz_sh_peers xz_sh_state xz_sh_stats xz_sh_total; do
    ! bpftool map show name "$map_name" 2>/dev/null | grep -q "$map_name"
done

echo "PASS: isolated SOCKHASH capability selftest and owned-object cleanup"
