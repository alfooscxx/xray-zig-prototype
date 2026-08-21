#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 /absolute/path/xray-zig /absolute/path/control.json /absolute/path/sockhash.json" >&2
    exit 2
fi

XRAY_BIN=$1
CONTROL_CONFIG=$2
SOCKHASH_CONFIG=$3
SCRIPT_DIR=$(CDPATH= cd "$(dirname "$0")" && pwd)
WAN_HARNESS=$SCRIPT_DIR/ebpf-sk-lookup-wan.sh
SOCKHASH_LOAD_CONCURRENCY=${SOCKHASH_LOAD_CONCURRENCY:-8}
SOCKHASH_DOWNLOAD_BYTES=${SOCKHASH_DOWNLOAD_BYTES:-8388608}
SOCKHASH_LOAD_TIMEOUT_SECONDS=${SOCKHASH_LOAD_TIMEOUT_SECONDS:-180}
export SOCKHASH_LOAD_CONCURRENCY SOCKHASH_DOWNLOAD_BYTES SOCKHASH_LOAD_TIMEOUT_SECONDS

[ -x "$XRAY_BIN" ] || { echo "xray-zig is not executable: $XRAY_BIN" >&2; exit 1; }
[ -r "$CONTROL_CONFIG" ] || { echo "control config is not readable: $CONTROL_CONFIG" >&2; exit 1; }
[ -r "$SOCKHASH_CONFIG" ] || { echo "SOCKHASH config is not readable: $SOCKHASH_CONFIG" >&2; exit 1; }
[ -x "$WAN_HARNESS" ] || { echo "WAN harness is not executable: $WAN_HARNESS" >&2; exit 1; }

if grep -q '"sockhashOffload"' "$CONTROL_CONFIG"; then
    echo "control config unexpectedly enables sockhashOffload" >&2
    exit 1
fi
grep -q '"sockhashOffload"' "$SOCKHASH_CONFIG" || {
    echo "SOCKHASH config does not enable sockhashOffload" >&2
    exit 1
}

run_arm() {
    label=$1
    monitoring=$2
    config=$3
    echo "== $label monitoring=$monitoring =="
    XRAY_ZIG_MONITORING=$monitoring "$WAN_HARNESS" "$XRAY_BIN" "$config"
}

run_arm "raw-reactor control" 0 "$CONTROL_CONFIG"
run_arm "raw-reactor instrumented" 1 "$CONTROL_CONFIG"
run_arm "SOCKHASH control" 0 "$SOCKHASH_CONFIG"
run_arm "SOCKHASH instrumented" 1 "$SOCKHASH_CONFIG"

echo "PASS: isolated raw-reactor/SOCKHASH and monitoring-disabled/enabled A/B completed with independent namespace cleanup"
