package internal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	namespace = "vault_unsealer"
)

var (
	VersionMetric = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "version",
		Help:      "Version information, always 1.",
	}, []string{"version", "hash"})

	UptimeMetric = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "start_time_seconds",
		Help:      "Start time of the process as unix timestamp.",
	})

	UnsealKeyRetrievalErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "unseal",
		Name:      "key_retrieval_errors_total",
		Help:      "Number of failed attempts to retrieve an unseal key.",
	}, []string{"cluster", "retriever"})

	KeyRetrieverHealthy = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "unseal",
		Name:      "key_retriever_healthy_bool",
		Help:      "Result of the last check of a key source, bypassing caches: healthy (1) or failing (0).",
	}, []string{"cluster", "retriever"})

	LastCheck = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "agent",
		Name:      "last_check_timestamp_seconds",
		Help:      "Unix timestamp of the last seal status check of a vault instance.",
	}, []string{"vault_instance"})

	UnsealedStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "agent",
		Name:      "unsealed_bool",
		Help:      "Indicates whether a vault instance is unsealed (1) or sealed (0).",
	}, []string{"vault_instance"})

	Instances = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Subsystem: "agent",
		Name:      "instances",
		Help:      "Number of instances of a cluster found by the last successful discovery.",
	}, []string{"cluster"})

	EndpointDiscoveryErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "agent",
		Name:      "endpoint_discovery_errors_total",
		Help:      "Number of failed attempts to discover the instances of a cluster, e.g. via DNS SRV.",
	}, []string{"cluster"})

	UnsealErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "agent",
		Name:      "unseal_errors_total",
		Help:      "Number of errors while checking or unsealing a vault instance.",
	}, []string{"error", "vault_instance"})
)

// deleteInstanceMetrics removes all metrics of an instance that is no longer part of its cluster, so it doesn't trigger
// alerts on stale values.
func deleteInstanceMetrics(instance string) {
	labels := prometheus.Labels{"vault_instance": instance}
	LastCheck.DeletePartialMatch(labels)
	UnsealedStatus.DeletePartialMatch(labels)
	UnsealErrors.DeletePartialMatch(labels)
}

const metricsShutdownTimeout = 5 * time.Second

// StartMetricsServer serves metrics until the context is cancelled.
func StartMetricsServer(ctx context.Context, addr string) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 3 * time.Second,
		ReadTimeout:       3 * time.Second,
		WriteTimeout:      3 * time.Second,
		IdleTimeout:       90 * time.Second,
		Handler:           mux,
	}

	errChan := make(chan error, 1)
	go func() {
		errChan <- server.ListenAndServe()
	}()

	select {
	case err := <-errChan:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("could not start metrics server: %w", err)
		}
		return nil
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), metricsShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("could not shut down metrics server: %w", err)
		}
		return nil
	}
}
