#!/usr/bin/env bash
set -euo pipefail

proxy="${XRAY_FIELD_PROXY:-${XRAY_ZIG_SOCKS_PROXY:-}}"
streams="${XRAY_ZIG_STREAMS:-4}"
bytes_per_stream="${XRAY_ZIG_BYTES_PER_STREAM:-8388608}"
connect_timeout="${XRAY_ZIG_CONNECT_TIMEOUT:-15}"
max_time="${XRAY_ZIG_MAX_TIME:-120}"
output_dir="${XRAY_ZIG_RESULTS_DIR:-$(mktemp -d)}"

mkdir -p "${output_dir}"
results="${output_dir}/transfers.tsv"
printf 'stream\thttp_code\tbytes\ttotal_s\tspeed_Bps\texit\n' >"${results}"

run_transfer() {
  local index="$1"
  local metrics rc
  local proxy_args=()
  if [[ -n "${proxy}" ]]; then
    proxy_args=(--proxy "${proxy}")
  fi
  set +e
  metrics="$(curl --silent --show-error --output /dev/null \
    "${proxy_args[@]}" \
    --connect-timeout "${connect_timeout}" \
    --max-time "${max_time}" \
    --write-out $'%{http_code}\t%{size_download}\t%{time_total}\t%{speed_download}' \
    "https://speed.cloudflare.com/__down?bytes=${bytes_per_stream}" \
    2>"${output_dir}/stream-${index}.stderr")"
  rc=$?
  set -e
  if [[ -z "${metrics}" ]]; then metrics=$'000\t0\t0\t0'; fi
  printf '%s\t%s\t%s\n' "${index}" "${metrics}" "${rc}" >>"${results}"
}

export -f run_transfer
export proxy bytes_per_stream connect_timeout max_time output_dir results

started_ns="$(date +%s%N)"
seq 1 "${streams}" | xargs -P "${streams}" -n 1 bash -c 'run_transfer "$1"' _
finished_ns="$(date +%s%N)"

elapsed_ms=$(((finished_ns - started_ns) / 1000000))
awk -F '\t' -v elapsed_ms="$elapsed_ms" '
  NR == 1 {next}
  {
    streams++
    if ($6 == 0 && $2 >= 200 && $2 < 300) ok++
    bytes += $3
  }
  END {
    seconds=elapsed_ms/1000
    printf "result=%d/%d bytes=%.0f elapsed_s=%.3f aggregate_MiBps=%.3f\n", ok, streams, bytes, seconds, seconds ? bytes/1048576/seconds : 0
    if (ok != streams) exit 1
  }
' "$results"
echo "results=$results"
