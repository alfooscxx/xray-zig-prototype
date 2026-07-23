#!/usr/bin/env bash
set -euo pipefail

proxy="${XRAY_FIELD_PROXY:-${XRAY_ZIG_SOCKS_PROXY:-}}"
concurrency="${XRAY_ZIG_CONCURRENCY:-16}"
requests_per_origin="${XRAY_ZIG_REQUESTS_PER_ORIGIN:-16}"
connect_timeout="${XRAY_ZIG_CONNECT_TIMEOUT:-15}"
max_time="${XRAY_ZIG_MAX_TIME:-45}"
output_dir="${XRAY_ZIG_RESULTS_DIR:-$(mktemp -d)}"

if ! command -v curl >/dev/null 2>&1; then
  echo "curl is required" >&2
  exit 2
fi

mkdir -p "${output_dir}"
results="${output_dir}/requests.tsv"
printf 'origin\trequest\thttp_code\tbytes\tconnect_s\ttls_s\ttotal_s\texit\n' >"${results}"

origins=(
  "ordinary|https://www.iana.org/"
  "cloudflare|https://www.cloudflare.com/"
  "fastly|https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc"
  "jsdelivr|https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"
)

run_request() {
  local origin="$1"
  local url="$2"
  local index="$3"
  local metrics rc
  local proxy_args=()

  if [[ -n "${proxy}" ]]; then
    proxy_args=(--proxy "${proxy}")
  fi

  set +e
  metrics="$(curl --silent --show-error --location --output /dev/null \
    "${proxy_args[@]}" \
    --connect-timeout "${connect_timeout}" \
    --max-time "${max_time}" \
    --write-out $'%{http_code}\t%{size_download}\t%{time_connect}\t%{time_appconnect}\t%{time_total}' \
    "${url}" 2>"${output_dir}/${origin}-${index}.stderr")"
  rc=$?
  set -e

  if [[ -z "${metrics}" ]]; then
    metrics=$'000\t0\t0\t0\t0'
  fi
  printf '%s\t%s\t%s\t%s\n' "${origin}" "${index}" "${metrics}" "${rc}" >>"${results}"
}

export -f run_request
export proxy connect_timeout max_time output_dir results

started_ns="$(date +%s%N)"
for entry in "${origins[@]}"; do
  origin="${entry%%|*}"
  url="${entry#*|}"
  for index in $(seq 1 "${requests_per_origin}"); do
    printf '%s\t%s\t%s\n' "${origin}" "${url}" "${index}"
  done
done | xargs -P "${concurrency}" -n 3 bash -c 'run_request "$1" "$2" "$3"' _
finished_ns="$(date +%s%N)"

printf '%-12s %8s %12s %12s %12s\n' "origin" "result" "bytes" "mean_s" "max_s"
awk -F '\t' '
  NR == 1 { next }
  {
    total[$1]++
    if ($8 == 0 && $3 >= 200 && $3 < 400) ok[$1]++
    bytes[$1] += $4
    latency[$1] += $7
    if ($7 > max_latency[$1]) max_latency[$1] = $7
  }
  END {
    for (name in total) {
      printf "%-12s %3d/%-4d %12.0f %12.3f %12.3f\n", name, ok[name], total[name], bytes[name], latency[name] / total[name], max_latency[name]
    }
  }
' "${results}" | sort

elapsed_ms=$(((finished_ns - started_ns) / 1000000))
failures="$(awk -F '\t' 'NR > 1 && !($8 == 0 && $3 >= 200 && $3 < 400) {n++} END {print n + 0}' "${results}")"
echo "elapsed_ms=${elapsed_ms} failures=${failures} results=${results}"
[[ "${failures}" == 0 ]]
