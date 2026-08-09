#!/bin/sh
set -eu

repo_dir=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
quick=$repo_dir/contrib/xray-zig-quick
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/xray-zig-quick-test.XXXXXX")
state_dir=$test_dir/state
bin_dir=$test_dir/bin
firewall_log=$test_dir/firewall.log
firewall_fail_file=$test_dir/firewall.fail
mkdir -p "$bin_dir"

cleanup() {
    status=$?
    trap - EXIT HUP INT TERM
    XRAY_ZIG_QUICK_STATE_DIR=$state_dir \
    XRAY_ZIG_QUICK_SKIP_ROOT=yes \
    XRAY_ZIG_QUICK_IPTABLES=$bin_dir/iptables \
    XRAY_ZIG_QUICK_IP6TABLES=$bin_dir/ip6tables \
        "$quick" down "$test_dir/router.conf" >/dev/null 2>&1 || true
    rm -rf "$test_dir"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

cat >"$bin_dir/xray-zig" <<'EOF'
#!/bin/sh
set -eu

command=$1
config=$3
case $command in
check)
    cat <<'SUMMARY'
config ok: 3 inbound(s), 1 outbound(s)
inbound redirect-ipv4: redirect on 0.0.0.0:12345
inbound redirect-ipv6: redirect on :::12346
inbound dns-in: dns on 0.0.0.0:15353
outbound direct: freedom
SUMMARY
    ;;
run)
    trap 'exit 0' TERM INT
    if [ "${config##*/}" != fail.json ]; then
        echo 'redirect inbound redirect-ipv4 listening on 0.0.0.0:12345'
        echo 'redirect inbound redirect-ipv6 listening on :::12346'
        echo 'dns inbound dns-in listening on 0.0.0.0:15353'
    fi
    while :; do sleep 1; done
    ;;
*) exit 2 ;;
esac
EOF

cat >"$bin_dir/iptables" <<'EOF'
#!/bin/sh
printf '%s %s\n' "${0##*/}" "$*" >>"$FIREWALL_LOG"
if [ -f "$FIREWALL_FAIL_FILE" ]; then
    case " $* " in
        *' -D '*) exit 1 ;;
    esac
fi
EOF
cp "$bin_dir/iptables" "$bin_dir/ip6tables"
chmod +x "$bin_dir/xray-zig" "$bin_dir/iptables" "$bin_dir/ip6tables"

: >"$test_dir/xray.json"
: >"$test_dir/fail.json"
cat >"$test_dir/router.conf" <<EOF
Config = xray.json
Binary = $bin_dir/xray-zig
LanInterface = br-lan,guest0
LogFile = $test_dir/xray.log
EOF

run_quick() {
    FIREWALL_LOG=$firewall_log \
    FIREWALL_FAIL_FILE=$firewall_fail_file \
    XRAY_ZIG_QUICK_STATE_DIR=$state_dir \
    XRAY_ZIG_QUICK_SKIP_ROOT=yes \
    XRAY_ZIG_QUICK_READY_TIMEOUT=1 \
    XRAY_ZIG_QUICK_IPTABLES=$bin_dir/iptables \
    XRAY_ZIG_QUICK_IP6TABLES=$bin_dir/ip6tables \
        "$quick" "$@"
}

check_output=$(run_quick check "$test_dir/router.conf")
printf '%s\n' "$check_output" | grep -q 'ipv4_redirect=12345 ipv6_redirect=12346 ipv4_dns=15353 ipv6_dns=off'

run_quick up "$test_dir/router.conf" >/dev/null
run_quick status router | grep -q 'router is up'
test -f "$state_dir/router.pid"

grep -q 'iptables -t nat -A XZQ_.* -p udp --dport 53 -j REDIRECT --to-ports 15353' "$firewall_log"
grep -q 'iptables -t nat -A XZQ_.* -m addrtype --dst-type LOCAL -j RETURN' "$firewall_log"
grep -q 'iptables -t nat -A XZQ_.* -p tcp -j REDIRECT --to-ports 12345' "$firewall_log"
grep -q 'iptables -t nat -I PREROUTING 1 -i br-lan -j XZQ_' "$firewall_log"
grep -q 'iptables -t nat -I PREROUTING 1 -i guest0 -j XZQ_' "$firewall_log"
grep -q 'ip6tables -t nat -A XZQ_.* -p tcp -j REDIRECT --to-ports 12346' "$firewall_log"
if grep -q 'ip6tables .* --dport 53' "$firewall_log"; then
    echo 'unexpected IPv6 DNS redirect without an IPv6 DNS inbound' >&2
    exit 1
fi

if run_quick up "$test_dir/router.conf" >/dev/null 2>&1; then
    echo 'duplicate up unexpectedly succeeded' >&2
    exit 1
fi

touch "$firewall_fail_file"
if run_quick down router >/dev/null 2>&1; then
    echo 'down unexpectedly stopped after firewall cleanup failed' >&2
    exit 1
fi
run_quick status router | grep -q 'router is up'
rm -f "$firewall_fail_file"

run_quick down router >/dev/null
if run_quick status router >/dev/null 2>&1; then
    echo 'status unexpectedly reported an inactive profile as up' >&2
    exit 1
fi
grep -q 'iptables -t nat -D PREROUTING -i br-lan -j XZQ_' "$firewall_log"
grep -q 'ip6tables -t nat -X XZQ_' "$firewall_log"

sed 's/Config = xray.json/Config = fail.json/' "$test_dir/router.conf" >"$test_dir/fail.conf"
if run_quick up "$test_dir/fail.conf" >/dev/null 2>&1; then
    echo 'startup without ready listeners unexpectedly succeeded' >&2
    exit 1
fi
test ! -f "$state_dir/fail.pid"

cat >"$test_dir/invalid.conf" <<EOF
Config = xray.json
Binary = $bin_dir/xray-zig
LanInterface = br-lan
Unknown = value
EOF
if run_quick check "$test_dir/invalid.conf" >/dev/null 2>&1; then
    echo 'unknown profile key unexpectedly succeeded' >&2
    exit 1
fi

echo 'xray-zig-quick tests passed'
