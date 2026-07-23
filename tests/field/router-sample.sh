#!/bin/sh
set -eu

target_pidfile="${XRAY_ZIG_PIDFILE:-/run/xray-zig/xray-zig.pid}"
sampler_pidfile="${XRAY_ZIG_SAMPLER_PIDFILE:-/run/xray-zig-field-sampler.pid}"
output="${XRAY_ZIG_SAMPLE_OUTPUT:-/run/xray-zig-field-samples.tsv}"
interval="${XRAY_ZIG_SAMPLE_INTERVAL:-1}"

sampler_alive() {
  test -f "$sampler_pidfile" || return 1
  sampler_pid=$(cat "$sampler_pidfile" 2>/dev/null || true)
  test -n "$sampler_pid" && test -r "/proc/$sampler_pid/cmdline" &&
    tr '\000' ' ' <"/proc/$sampler_pid/cmdline" | grep -q 'router-sample.sh run'
}

stop_sampler() {
  if sampler_alive; then
    kill "$(cat "$sampler_pidfile")" 2>/dev/null || true
  fi
  rm -f "$sampler_pidfile"
}

run_sampler() {
  pid=$(cat "$target_pidfile")
  kill -0 "$pid"
  hz=$(getconf CLK_TCK 2>/dev/null || echo 100)

  printf '# hz=%s\n' "$hz"
  printf 'epoch\tcpu_jiffies\trss_kb\tthreads\tfds\testablished\treclaimable_kb\n'
  while kill -0 "$pid" 2>/dev/null; do
    now=$(date +%s)
    jiffies=$(awk '{print $14 + $15}' "/proc/$pid/stat" 2>/dev/null || echo 0)
    rss=$(awk '/^VmRSS:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    threads=$(awk '/^Threads:/ {print $2}' "/proc/$pid/status" 2>/dev/null || echo 0)
    fds=$(ls "/proc/$pid/fd" 2>/dev/null | wc -l)
    established=$(netstat -nt 2>/dev/null | awk -v pid="$pid" '$6 == "ESTABLISHED" && $7 ~ (pid "/") {n++} END {print n + 0}')
    reclaimable=$(awk '/MemFree:|Buffers:|^Cached:/ {sum += $2} END {print sum + 0}' /proc/meminfo)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$now" "$jiffies" "$rss" "$threads" "$fds" "$established" "$reclaimable"
    sleep "$interval"
  done
}

summarize() {
  test -f "$output"
  hz=$(awk -F= '/^# hz=/ {print $2; exit}' "$output")
  hz=${hz:-100}
  awk -v hz="$hz" '
    $1 == "epoch" || /^#/ {next}
    !seen {st=$1; sj=$2; minmem=$7; seen=1}
    {
      et=$1; ej=$2
      if ($3 > rss) rss=$3
      if ($4 > threads) threads=$4
      if ($5 > fds) fds=$5
      if ($6 > established) established=$6
      if ($7 < minmem) minmem=$7
      samples++
    }
    END {
      elapsed=et-st
      cpu=(ej-sj)/hz
      printf "elapsed_s=%d cpu_s=%.2f cpu_pct=%.1f peak_rss_kb=%d peak_threads=%d peak_fds=%d peak_established=%d min_reclaimable_kb=%d samples=%d\n", elapsed, cpu, elapsed ? cpu*100/elapsed : 0, rss, threads, fds, established, minmem, samples
    }
  ' "$output"
}

case "${1:-run}" in
run)
  run_sampler
  ;;
start)
  stop_sampler
  "$0" run >"$output" 2>&1 </dev/null &
  echo $! >"$sampler_pidfile"
  sleep 1
  sampler_alive
  echo "sampler=$(cat "$sampler_pidfile") output=$output"
  ;;
stop)
  stop_sampler
  ;;
summary)
  summarize
  ;;
*)
  echo "Usage: $0 {run|start|stop|summary}" >&2
  exit 2
  ;;
esac
