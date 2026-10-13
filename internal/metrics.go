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

	UnsealErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Subsystem: "agent",
		Name:      "unseal_errors_total",
		Help:      "Number of errors while checking or unsealing a vault instance.",
	}, []string{"error", "vault_instance"})
)

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
