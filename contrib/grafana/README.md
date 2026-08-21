# xray-zig Grafana

`xray-zig-overview.json` is a datasource-agnostic dashboard for a Prometheus or
VictoriaMetrics datasource. Import it into Grafana and select the datasource
with the `DS_PROMETHEUS` input.

`xray-zig-alerts.yaml` contains correctness alerts only: missing readiness,
lost required BPF hooks, connection rejection, and SOCKHASH redirect errors.
Rate and utilization thresholds are intentionally omitted until repeatable
interleaved monitoring-disabled/enabled A/B measurements exist.

The router must expose metrics through the root-only collector and an existing
management-network exporter. Grafana and the time-series database do not run on
the router.
