#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 /absolute/path/xray-zig /absolute/path/lab-config.json" >&2
    exit 2
fi

XRAY_BIN=$1
CONFIG_FILE=$2
LAB_ID=$$
LAB_ROOT=/tmp/xz-ebpf-wan-$LAB_ID
CLIENT_NS=xz-wc-$LAB_ID
ROUTER_NS=xz-wr-$LAB_ID
SUFFIX=$((LAB_ID % 10000))
CLIENT_IF=xzwc$SUFFIX
ROUTER_IF=xzwr$SUFFIX
WAN_ROOT_IF=xzwb$SUFFIX
WAN_NS_IF=xzww$SUFFIX
TUN_IF=xztun0
XRAY_PID=
DHCP_PID=
CLIENT_JOBS=
BATCH_WATCHDOG_PID=
BPF_LINK_ID=
BPF_PROG_ID=
BPF_MAP4_ID=
BPF_MAP6_ID=
BPF_LISTENERS_ID=
SH_PARSER_ID=
SH_VERDICT_ID=
SH_TARGETS_ID=
SH_SOURCES_ID=
SH_PEERS_ID=
SH_STATE_ID=
SH_STATS_ID=
SH_TOTAL_ID=
BASE_MAP4_IDS=
BASE_MAP6_IDS=
OFFLOAD=0
DOWNLOAD_BYTES=${SOCKHASH_DOWNLOAD_BYTES:-1048576}
LOAD_CONCURRENCY=${SOCKHASH_LOAD_CONCURRENCY:-1}
LOAD_BATCH_TIMEOUT=${SOCKHASH_LOAD_TIMEOUT_SECONDS:-180}

if grep -q '"sockhashOffload"' "$CONFIG_FILE"; then
    OFFLOAD=1
fi

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

release_dhcp() {
    [ -n "$DHCP_PID" ] || return
    kill -USR2 "$DHCP_PID" 2>/dev/null || true
    sleep 1
    terminate_pid "$DHCP_PID"
    DHCP_PID=
}

run_bounded() {
    "$@" &
    cmd_pid=$!
    (
        sleep 60
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

named_map_ids() {
    bpftool map show name "$1" 2>/dev/null |
        sed -n 's/^\([0-9][0-9]*\):.*/\1/p' || true
}

new_named_map_id() {
    map_name=$1
    baseline_ids=$2
    found=
    for candidate_id in $(named_map_ids "$map_name"); do
        case " $baseline_ids " in
            *" $candidate_id "*) continue ;;
        esac
        [ -z "$found" ] || {
            echo "multiple new BPF maps named $map_name" >&2
            return 1
        }
        found=$candidate_id
    done
    [ -n "$found" ] || {
        echo "no new BPF map named $map_name" >&2
        return 1
    }
    printf '%s\n' "$found"
}

map_u64_at() {
    map_id=$1
    byte_offset=$2
    bpftool map lookup id "$map_id" key hex 00 00 00 00 | awk -v byte_offset="$byte_offset" '
        function hex(s, i, n, c) {
            s = tolower(s); n = 0
            for (i = 1; i <= length(s); i++) {
                c = index("0123456789abcdef", substr(s, i, 1)) - 1
                n = n * 16 + c
            }
            return n
        }
        /^value:/ { in_value = 1; next }
        in_value {
            for (i = 1; i <= NF; i++) {
                token = tolower($i)
                if (token !~ /^[0-9a-f][0-9a-f]$/) continue
                if (value_index == byte_offset) multiplier = 1
                if (value_index >= byte_offset && value_index < byte_offset + 8) {
                    total += hex(token) * multiplier
                    multiplier *= 256
                }
                value_index++
            }
        }
        END {
            if (value_index < byte_offset + 8) exit 1
            printf "%.0f\n", total
        }
    '
}

print_client_diagnostics() {
    echo "== isolated WAN HTTPS clients ==" >&2
    if [ -e "$LAB_ROOT/batch-timeout" ]; then
        echo "batch_watchdog_fired=yes timeout_seconds=$LOAD_BATCH_TIMEOUT" >&2
    else
        echo "batch_watchdog_fired=no timeout_seconds=$LOAD_BATCH_TIMEOUT" >&2
    fi
    index=1
    while [ "$index" -le "$LOAD_CONCURRENCY" ]; do
        status_file="$LAB_ROOT/client-$index.status"
        output_file="$LAB_ROOT/https-$index.bin"
        log_file="$LAB_ROOT/client-$index.log"
        client_status=not-recorded
        output_size=missing
        log_size=missing
        [ ! -r "$status_file" ] || client_status=$(sed -n '1p' "$status_file")
        [ ! -f "$output_file" ] || output_size=$(wc -c <"$output_file")
        [ ! -f "$log_file" ] || log_size=$(wc -c <"$log_file")
        echo "-- client=$index status=$client_status output_bytes=$output_size log_bytes=$log_size --" >&2
        if [ -r "$log_file" ]; then
            sed -n '1,80p' "$log_file" >&2
        fi
        index=$((index + 1))
    done
}

cleanup() {
    status=$?
    trap - EXIT INT TERM HUP
    set +e
    if [ -n "$BATCH_WATCHDOG_PID" ]; then
        kill "$BATCH_WATCHDOG_PID" 2>/dev/null
        wait "$BATCH_WATCHDOG_PID" 2>/dev/null
    fi
    for client_job in $CLIENT_JOBS; do
        client_pid=${client_job%%:*}
        client_index=${client_job#*:}
        status_file="$LAB_ROOT/client-$client_index.status"
        [ -e "$status_file" ] && continue
        kill -KILL "$client_pid" 2>/dev/null
        wait "$client_pid" 2>/dev/null
        printf '%s\n' "$?" >"$status_file"
    done
    if [ -n "$XRAY_PID" ]; then
        terminate_pid "$XRAY_PID"
    fi
    release_dhcp
    if [ "$status" -ne 0 ]; then
        print_client_diagnostics
        echo "== isolated WAN xray log ==" >&2
        sed -n '1,260p' "$LAB_ROOT/xray.log" >&2 2>/dev/null
        echo "== Vision trace frame summary ==" >&2
        awk '
            /^vision [0-9]+ downlink (initial )?frame command=/ {
                id = $2
                frames[id]++
                for (i = 1; i <= NF; i++) {
                    if ($i ~ /^command=/) {
                        split($i, field, "=")
                        command = field[2]
                    }
                }
                if (command == 0) continues[id]++
                else if (command == 1) ends[id]++
                else if (command == 2) directs[id]++
                else unknown[id]++
                last[id] = command
            }
            /^vision [0-9]+ downlink chunk / {
                chunks[$2]++
                if ($0 ~ / read_direct=true$/) direct_chunks[$2]++
            }
            END {
                for (id in frames) {
                    printf "vision=%s frames=%d continue=%d end=%d direct=%d unknown=%d last=%s chunks=%d direct_chunks=%d\n", \
                        id, frames[id], continues[id], ends[id], directs[id], unknown[id], \
                        last[id], chunks[id], direct_chunks[id]
                }
            }
        ' "$LAB_ROOT/xray.log" >&2 2>/dev/null || true
        grep -E '^vision [0-9]+ (classified|raw-reactor-handoff|sockhash-handoff|uplink|downlink|Timeout) target=' \
            "$LAB_ROOT/xray.log" >&2 2>/dev/null || true
        echo "== isolated WAN DHCP log ==" >&2
        sed -n '1,160p' "$LAB_ROOT/dhcp.log" >&2 2>/dev/null
    fi
    ip netns del "$CLIENT_NS" 2>/dev/null
    ip netns del "$ROUTER_NS" 2>/dev/null
    ip link del "$WAN_ROOT_IF" 2>/dev/null
    index=1
    while [ "$index" -le "$LOAD_CONCURRENCY" ]; do
        rm -f "$LAB_ROOT/https-$index.bin" "$LAB_ROOT/client-$index.log" \
            "$LAB_ROOT/client-$index.status"
        index=$((index + 1))
    done
    rm -f "$LAB_ROOT/xray.log" "$LAB_ROOT/dhcp.log" "$LAB_ROOT/dhcp-bound" \
        "$LAB_ROOT/dhcp-address" "$LAB_ROOT/udhcpc.sh" \
        "$LAB_ROOT/resolv.conf" "$LAB_ROOT/https-client.sh" \
        "$LAB_ROOT/batch-timeout"
    rmdir "$LAB_ROOT" 2>/dev/null
    exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(uname -m)" = aarch64 ] || {
    echo "refusing to run: this lab is restricted to the AArch64 field router" >&2
    exit 1
}
[ -x "$XRAY_BIN" ] || { echo "xray-zig is not executable: $XRAY_BIN" >&2; exit 1; }
[ -r "$CONFIG_FILE" ] || { echo "lab config is not readable: $CONFIG_FILE" >&2; exit 1; }
case "$DOWNLOAD_BYTES:$LOAD_CONCURRENCY:$LOAD_BATCH_TIMEOUT" in
    *[!0-9:]* | 0:* | *:0:* | *:0)
        echo "SOCKHASH download, concurrency, and timeout values must be positive integers" >&2
        exit 1
        ;;
esac
[ "$DOWNLOAD_BYTES" -le 1073741824 ] || { echo "download size exceeds the 1 GiB per-flow lab bound" >&2; exit 1; }
[ "$LOAD_CONCURRENCY" -le 64 ] || { echo "load concurrency exceeds the 64-flow lab bound" >&2; exit 1; }
[ "$LOAD_BATCH_TIMEOUT" -le 900 ] || { echo "batch timeout exceeds the 900-second lab bound" >&2; exit 1; }
[ -c /dev/net/tun ] || { echo "/dev/net/tun is unavailable" >&2; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool is required" >&2; exit 1; }
command -v udhcpc >/dev/null || { echo "udhcpc is required" >&2; exit 1; }
command -v uclient-fetch >/dev/null || { echo "uclient-fetch is required" >&2; exit 1; }
command -v mount >/dev/null || { echo "mount is required" >&2; exit 1; }
command -v ip >/dev/null || { echo "ip-full is required" >&2; exit 1; }
[ -r /etc/ssl/certs/ca-certificates.crt ] || { echo "CA bundle is required" >&2; exit 1; }
ip -V 2>&1 | grep -q 'iproute2' || { echo "BusyBox ip is insufficient; install ip-full" >&2; exit 1; }
ip link show br-lan >/dev/null 2>&1 || { echo "br-lan is required" >&2; exit 1; }
ip -o -4 address show dev br-lan | grep -q ' 192\.168\.8\.1/24 ' || {
    echo "refusing to run: expected br-lan 192.168.8.1/24" >&2
    exit 1
}
ip netns list | grep -Eq "^$CLIENT_NS|^$ROUTER_NS" && { echo "lab namespace collision" >&2; exit 1; }
ip link show "$WAN_ROOT_IF" >/dev/null 2>&1 && { echo "lab WAN interface collision" >&2; exit 1; }
if bpftool prog show name xz_sk_lookup 2>/dev/null | grep -q 'xz_sk_lookup'; then
    echo "refusing to run: BPF program name xz_sk_lookup already exists" >&2
    exit 1
fi
BASE_MAP4_IDS=$(named_map_ids xz_fake4)
BASE_MAP6_IDS=$(named_map_ids xz_fake6)
if bpftool map show name xz_listeners 2>/dev/null | grep -q xz_listeners; then
    echo "refusing to run: BPF map name xz_listeners already exists" >&2
    exit 1
fi
if [ "$OFFLOAD" -eq 1 ]; then
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
fi

"$XRAY_BIN" check -config "$CONFIG_FILE" >/dev/null
mkdir "$LAB_ROOT"
chmod 700 "$LAB_ROOT"
export LAB_ROOT
cat >"$LAB_ROOT/udhcpc.sh" <<'SH'
#!/bin/sh
set -eu
case "$1" in
    bound | renew)
        gateway=${router%% *}
        [ -n "$gateway" ]
        ip address flush dev "$interface" scope global
        ip address add "$ip/24" dev "$interface"
        ip route replace default via "$gateway" dev "$interface"
        printf '%s\n' "$ip" >"$LAB_ROOT/dhcp-address"
        : >"$LAB_ROOT/dhcp-bound"
        ;;
    deconfig)
        ip route del default dev "$interface" 2>/dev/null || true
        ip address flush dev "$interface" scope global 2>/dev/null || true
        ;;
esac
SH
chmod 700 "$LAB_ROOT/udhcpc.sh"
cat >"$LAB_ROOT/resolv.conf" <<'EOF'
nameserver 192.0.2.1
options timeout:2 attempts:2
EOF
cat >"$LAB_ROOT/https-client.sh" <<'SH'
#!/bin/sh
set -eu
index=$1
mount --bind "$LAB_ROOT/resolv.conf" /etc/resolv.conf
exec uclient-fetch -4 --quiet --timeout=45 --no-proxy \
    --ca-certificate=/etc/ssl/certs/ca-certificates.crt \
    -O "$LAB_ROOT/https-$index.bin" \
    "https://speed.cloudflare.com/__down?bytes=$LAB_DOWNLOAD_BYTES"
SH
chmod 700 "$LAB_ROOT/https-client.sh"

ip netns add "$CLIENT_NS"
ip netns add "$ROUTER_NS"
ip link add "$CLIENT_IF" type veth peer name "$ROUTER_IF"
ip link set "$CLIENT_IF" netns "$CLIENT_NS"
ip link set "$ROUTER_IF" netns "$ROUTER_NS"

ip -n "$CLIENT_NS" link set lo up
ip -n "$ROUTER_NS" link set lo up
ip -n "$CLIENT_NS" address add 192.0.2.2/30 dev "$CLIENT_IF"
ip -n "$ROUTER_NS" address add 192.0.2.1/30 dev "$ROUTER_IF"
ip -n "$CLIENT_NS" -6 address add fd00:eb9f::2/64 dev "$CLIENT_IF" nodad
ip -n "$ROUTER_NS" -6 address add fd00:eb9f::1/64 dev "$ROUTER_IF" nodad
ip -n "$CLIENT_NS" link set "$CLIENT_IF" up
ip -n "$ROUTER_NS" link set "$ROUTER_IF" up

ip -n "$ROUTER_NS" route add local 198.18.254.1/32 dev lo
ip -n "$ROUTER_NS" -6 route add local fd00:7872:6179:eb9f::1/128 dev lo
ip -n "$CLIENT_NS" route add 198.18.254.1/32 via 192.0.2.1 dev "$CLIENT_IF"
ip -n "$CLIENT_NS" -6 route add fd00:7872:6179:eb9f::1/128 via fd00:eb9f::1 dev "$CLIENT_IF"

# A second veth makes the router namespace an ordinary DHCP LAN client. The
# existing LAN-to-WAN forwarding/NAT policy is reused unchanged; the lab does
# not add, read, or modify firewall rules.
ip link add "$WAN_ROOT_IF" type veth peer name "$WAN_NS_IF"
ip link set "$WAN_NS_IF" netns "$ROUTER_NS"
ip link set "$WAN_ROOT_IF" master br-lan
ip link set "$WAN_ROOT_IF" up
ip -n "$ROUTER_NS" link set "$WAN_NS_IF" up

ip netns exec "$ROUTER_NS" env LAB_ROOT="$LAB_ROOT" \
    udhcpc -f -n -t 4 -T 2 -i "$WAN_NS_IF" -s "$LAB_ROOT/udhcpc.sh" \
    >"$LAB_ROOT/dhcp.log" 2>&1 &
DHCP_PID=$!
attempt=0
while [ ! -e "$LAB_ROOT/dhcp-bound" ]; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 15 ] || { echo "isolated WAN DHCP did not bind" >&2; exit 1; }
    kill -0 "$DHCP_PID" 2>/dev/null || { echo "isolated WAN DHCP exited" >&2; exit 1; }
    sleep 1
done
ip -n "$ROUTER_NS" route show default | grep -q "dev $WAN_NS_IF"
run_bounded ip netns exec "$ROUTER_NS" ping -c 1 -W 5 1.1.1.1 >/dev/null

ip netns exec "$ROUTER_NS" "$XRAY_BIN" run -config "$CONFIG_FILE" >"$LAB_ROOT/xray.log" 2>&1 &
XRAY_PID=$!
attempt=0
while ! ip -n "$ROUTER_NS" link show "$TUN_IF" >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    [ "$attempt" -lt 20 ] || { echo "isolated WAN xray-zig did not create its TUN" >&2; exit 1; }
    kill -0 "$XRAY_PID" 2>/dev/null || { echo "isolated WAN xray-zig exited" >&2; exit 1; }
    sleep 1
done

BPF_PROG_ID=$(bpftool prog show name xz_sk_lookup | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
BPF_MAP4_ID=$(new_named_map_id xz_fake4 "$BASE_MAP4_IDS")
BPF_MAP6_ID=$(new_named_map_id xz_fake6 "$BASE_MAP6_IDS")
BPF_LISTENERS_ID=$(bpftool map show name xz_listeners | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
[ -n "$BPF_PROG_ID" ] && [ -n "$BPF_MAP4_ID" ] && [ -n "$BPF_MAP6_ID" ] && [ -n "$BPF_LISTENERS_ID" ]
BPF_LINK_ID=$(bpftool link show | awk -v prog_id="$BPF_PROG_ID" '
    $0 ~ ("prog[[:space:]]+" prog_id "([[:space:]]|$)") {
        gsub(":", "", $1)
        print $1
        exit
    }
')
[ -n "$BPF_LINK_ID" ]
if [ "$OFFLOAD" -eq 1 ]; then
    SH_PARSER_ID=$(bpftool prog show name xz_sh_parser | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
    SH_VERDICT_ID=$(bpftool prog show name xz_sh_verdict | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
    SH_TARGETS_ID=$(bpftool map show name xz_sh_targets | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
    SH_SOURCES_ID=$(bpftool map show name xz_sh_sources | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
    SH_PEERS_ID=$(bpftool map show name xz_sh_peers | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
    SH_STATE_ID=$(bpftool map show name xz_sh_state | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
    SH_STATS_ID=$(bpftool map show name xz_sh_stats | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
    SH_TOTAL_ID=$(bpftool map show name xz_sh_total | sed -n 's/^\([0-9][0-9]*\):.*/\1/p')
    [ -n "$SH_PARSER_ID" ] && [ -n "$SH_VERDICT_ID" ] &&
        [ -n "$SH_TARGETS_ID" ] && [ -n "$SH_SOURCES_ID" ] &&
        [ -n "$SH_PEERS_ID" ] && [ -n "$SH_STATE_ID" ] &&
        [ -n "$SH_STATS_ID" ] && [ -n "$SH_TOTAL_ID" ]
    bpftool prog show id "$SH_PARSER_ID" | grep -q ' sk_skb '
    bpftool prog show id "$SH_VERDICT_ID" | grep -q ' sk_skb '
    bpftool map show id "$SH_TARGETS_ID" | grep -q ' sockhash '
    bpftool map show id "$SH_SOURCES_ID" | grep -q ' sockhash '
fi
if ip -n "$ROUTER_NS" route show dev "$TUN_IF" | grep -q .; then
    echo "test TUN unexpectedly owns an IPv4 route" >&2
    exit 1
fi
if ip -n "$ROUTER_NS" -6 route show dev "$TUN_IF" | grep -q .; then
    echo "test TUN unexpectedly owns an IPv6 route" >&2
    exit 1
fi

cpu_start=$(awk '{print $14 + $15}' "/proc/$XRAY_PID/stat")
elapsed_start=$(date +%s)
index=1
while [ "$index" -le "$LOAD_CONCURRENCY" ]; do
    ip netns exec "$CLIENT_NS" env LAB_ROOT="$LAB_ROOT" LAB_DOWNLOAD_BYTES="$DOWNLOAD_BYTES" \
        "$LAB_ROOT/https-client.sh" "$index" >"$LAB_ROOT/client-$index.log" 2>&1 &
    client_pid=$!
    CLIENT_JOBS="$CLIENT_JOBS $client_pid:$index"
    index=$((index + 1))
done
(
    sleep "$LOAD_BATCH_TIMEOUT"
    : >"$LAB_ROOT/batch-timeout"
    for client_pid in $(ip netns pids "$CLIENT_NS" 2>/dev/null); do
        kill -KILL "$client_pid" 2>/dev/null
    done
) &
BATCH_WATCHDOG_PID=$!
batch_status=0
failed_clients=0
set +e
for client_job in $CLIENT_JOBS; do
    client_pid=${client_job%%:*}
    client_index=${client_job#*:}
    wait "$client_pid"
    client_status=$?
    printf '%s\n' "$client_status" >"$LAB_ROOT/client-$client_index.status"
    if [ "$client_status" -ne 0 ]; then
        failed_clients=$((failed_clients + 1))
        [ "$batch_status" -ne 0 ] || batch_status=$client_status
    fi
done
set -e
kill "$BATCH_WATCHDOG_PID" 2>/dev/null || true
wait "$BATCH_WATCHDOG_PID" 2>/dev/null || true
BATCH_WATCHDOG_PID=
[ "$batch_status" -eq 0 ] || {
    echo "bounded HTTPS load clients failed: count=$failed_clients first_status=$batch_status" >&2
    exit 1
}
elapsed_end=$(date +%s)
cpu_end=$(awk '{print $14 + $15}' "/proc/$XRAY_PID/stat")
elapsed_seconds=$((elapsed_end - elapsed_start))
[ "$elapsed_seconds" -gt 0 ] || elapsed_seconds=1
cpu_ticks=$((cpu_end - cpu_start))

download_bytes=0
index=1
while [ "$index" -le "$LOAD_CONCURRENCY" ]; do
    output="$LAB_ROOT/https-$index.bin"
    [ -f "$output" ]
    flow_bytes=$(wc -c <"$output")
    [ "$flow_bytes" -ge "$DOWNLOAD_BYTES" ]
    download_bytes=$((download_bytes + flow_bytes))
    index=$((index + 1))
done
throughput_bytes_per_second=$((download_bytes / elapsed_seconds))
bpftool map lookup id "$BPF_MAP4_ID" key hex c6 12 fe 01 >/dev/null
established_count=$(grep -Ec 'vless [0-9]+ established target=speed\.cloudflare\.com:443 client_tls=true' "$LAB_ROOT/xray.log")
[ "$established_count" -ge "$LOAD_CONCURRENCY" ]
if [ "$OFFLOAD" -eq 1 ]; then
    handoff_count=$(grep -Ec 'vision [0-9]+ sockhash-handoff target=speed\.cloudflare\.com:443 tls=true tls12=true xtls=true write_direct=true read_direct=true' "$LAB_ROOT/xray.log")
    [ "$handoff_count" -ge "$LOAD_CONCURRENCY" ]
    attempt=0
    while [ "$(grep -c '^sockhash-close ' "$LAB_ROOT/xray.log" || true)" -lt "$LOAD_CONCURRENCY" ]; do
        attempt=$((attempt + 1))
        [ "$attempt" -lt 10 ] || { echo "SOCKHASH flow did not close within the bounded wait" >&2; exit 1; }
        sleep 1
    done
    close_summary=$(awk '
        /^sockhash-close / {
            count++
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^upstream_bytes=/) { split($i, a, "="); bytes += a[2] }
                if ($i ~ /^errors=/) { split($i, a, "="); errors += a[2] }
            }
        }
        END { printf "%d %.0f %.0f\n", count, bytes, errors }
    ' "$LAB_ROOT/xray.log")
    set -- $close_summary
    [ "$1" -ge "$LOAD_CONCURRENCY" ]
    [ "$2" -ge "$download_bytes" ]
    [ "$3" -eq 0 ]

    aggregate_bytes=$(map_u64_at "$SH_TOTAL_ID" 0)
    aggregate_errors=$(map_u64_at "$SH_TOTAL_ID" 16)
    [ "$aggregate_bytes" -ge "$download_bytes" ]
    [ "$aggregate_errors" -eq 0 ]
else
    handoff_count=$(grep -Ec 'vision [0-9]+ raw-reactor-handoff target=speed\.cloudflare\.com:443 tls=true tls12=true xtls=true write_direct=true read_direct=true' "$LAB_ROOT/xray.log")
    [ "$handoff_count" -ge "$LOAD_CONCURRENCY" ]
fi
kill -0 "$DHCP_PID"
echo "PASS WAN HTTPS speed.cloudflare.com flows=$LOAD_CONCURRENCY bytes=$download_bytes elapsed_s=$elapsed_seconds throughput_Bps=$throughput_bytes_per_second cpu_ticks=$cpu_ticks certificate=verified offload=$OFFLOAD"

terminate_pid "$XRAY_PID"
XRAY_PID=

! ip -n "$ROUTER_NS" link show "$TUN_IF" >/dev/null 2>&1
! bpftool link show id "$BPF_LINK_ID" >/dev/null 2>&1
! bpftool prog show id "$BPF_PROG_ID" >/dev/null 2>&1
! bpftool map show id "$BPF_MAP4_ID" >/dev/null 2>&1
! bpftool map show id "$BPF_MAP6_ID" >/dev/null 2>&1
! bpftool map show id "$BPF_LISTENERS_ID" >/dev/null 2>&1
for baseline_id in $BASE_MAP4_IDS $BASE_MAP6_IDS; do
    bpftool map show id "$baseline_id" >/dev/null
done
if [ "$OFFLOAD" -eq 1 ]; then
    ! bpftool prog show id "$SH_PARSER_ID" >/dev/null 2>&1
    ! bpftool prog show id "$SH_VERDICT_ID" >/dev/null 2>&1
    ! bpftool map show id "$SH_TARGETS_ID" >/dev/null 2>&1
    ! bpftool map show id "$SH_SOURCES_ID" >/dev/null 2>&1
    ! bpftool map show id "$SH_PEERS_ID" >/dev/null 2>&1
    ! bpftool map show id "$SH_STATE_ID" >/dev/null 2>&1
    ! bpftool map show id "$SH_STATS_ID" >/dev/null 2>&1
    ! bpftool map show id "$SH_TOTAL_ID" >/dev/null 2>&1
fi

echo "PASS: isolated FakeDNS -> SK_LOOKUP -> VLESS/REALITY/Vision -> WAN HTTPS handoff offload=$OFFLOAD"
