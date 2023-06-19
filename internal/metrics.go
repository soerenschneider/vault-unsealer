package internal

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"net/http"
)

const (
	namespace = "vault_unsealer"
)

var (
	UptimeMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "start_time_seconds",
	})

	UnsealKeyRetrievalErrors = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "unseal",
		Name:      "key_retrieval_errors_total",
	})

	LastCheck = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "agent",
		Name:      "last_check_timestamp_seconds",
	}, []string{"vault_instance"})

	UnsealedStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "agent",
		Name:      "sealed_status_bool",
		Help:      "Indicates whether a vault instance is unsealed (1) or sealed (0).",
	}, []string{"vault_instance"})

	UnsealErrors = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "agent",
		Name:      "unseal_errors_total",
	}, []string{"error", "vault_instance"})
)

func StartMetricsServer(addr string) error {
	http.Handle("/metrics", promhttp.Handler())
	return http.ListenAndServe(addr, nil)
}
