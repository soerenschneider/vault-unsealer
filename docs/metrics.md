# Metrics

Metrics are available in the Prometheus format and can be collected using Prometheus / Victoriametrics or similar.

All metrics are prefixed with `vault_unsealer`.

| Name                               | Type      | Labels                |
|------------------------------------|-----------|-----------------------|
| version                            | GaugeVec  | version, hash         |
| start_time_seconds                 | Gauge     |                       |
| key_retrieval_errors_total         | Counter   |                       |
| agent_last_check_timestamp_seconds | GaugeVec  | vault_instance        |
| agent_sealed_status_bool           | GaugeVec  | vault_instance        |
| unseal_errors_total                | GaugeVec  | error, vault_instance |