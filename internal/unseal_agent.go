package internal

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/soerenschneider/vault-unsealer/v2/internal/config"
	"github.com/soerenschneider/vault-unsealer/v2/internal/unsealing"
	"github.com/soerenschneider/vault-unsealer/v2/internal/vault"
	"go.uber.org/multierr"
)

type UnsealAgent struct {
	name          string
	keyRetrievers []unsealing.UnsealKeyRetriever
	client        vault.Client
	conf          config.ClusterConfig
	discovery     endpointDiscovery
	// endpoints are the instances found by the last successful discovery
	endpoints []string
}

func NewUnsealAgent(name string, conf config.ClusterConfig, client vault.Client, keyRetrievers []unsealing.UnsealKeyRetriever) (*UnsealAgent, error) {
	if client == nil {
		return nil, errors.New("no vault client provided")
	}

	if len(keyRetrievers) == 0 {
		return nil, errors.New("no key retrievers provided")
	}

	return &UnsealAgent{
		name:          name,
		client:        client,
		keyRetrievers: keyRetrievers,
		conf:          conf,
		discovery:     newEndpointDiscovery(conf),
	}, nil
}

// Run watches the cluster's instances until the context is cancelled.
func (u *UnsealAgent) Run(ctx context.Context) {
	u.checkKeyRetrievers(ctx)

	wg := sync.WaitGroup{}
	defer wg.Wait()
	// key sources are checked in a separate goroutine, so a slow key source doesn't delay checking the instances
	wg.Go(func() {
		u.runKeyChecks(ctx)
	})

	u.conditionallyUnsealInstances(ctx)

	ticker := time.NewTicker(time.Duration(u.conf.CheckIntervalSeconds) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.conditionallyUnsealInstances(ctx)
		}
	}
}

func (u *UnsealAgent) runKeyChecks(ctx context.Context) {
	ticker := time.NewTicker(u.conf.KeyCheckIntervalOrDefault())
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.checkKeyRetrievers(ctx)
		}
	}
}

// checkKeyRetrievers tests whether all key sources work, so failing ones are noticed before their keys are actually
// needed. Caches are bypassed, as a cached key doesn't tell anything about the source. Failures are reported but not
// fatal, as the key source may only be temporarily unavailable.
func (u *UnsealAgent) checkKeyRetrievers(ctx context.Context) {
	errs := make([]error, len(u.keyRetrievers))
	wg := sync.WaitGroup{}
	for idx, keyRetriever := range u.keyRetrievers {
		wg.Go(func() {
			if cachingRetriever, ok := keyRetriever.(unsealing.CachingUnsealKeyRetriever); ok {
				errs[idx] = cachingRetriever.Refresh(ctx)
			} else {
				_, errs[idx] = keyRetriever.RetrieveUnsealKey(ctx)
			}
		})
	}
	wg.Wait()

	failed := 0
	for idx, keyRetriever := range u.keyRetrievers {
		logger := log.With().Str("cluster", u.name).Str("retriever", keyRetriever.Name()).Logger()
		if errs[idx] != nil {
			logger.Error().Err(errs[idx]).Msg("Key source check failed")
			UnsealKeyRetrievalErrors.WithLabelValues(u.name, keyRetriever.Name()).Inc()
			KeyRetrieverHealthy.WithLabelValues(u.name, keyRetriever.Name()).Set(0)
			failed++
		} else {
			logger.Debug().Msg("Key source check succeeded")
			KeyRetrieverHealthy.WithLabelValues(u.name, keyRetriever.Name()).Set(1)
		}
	}

	if failed == len(u.keyRetrievers) {
		log.Error().Str("cluster", u.name).Msg("All key sources failed, sealed instances of this cluster can not be unsealed unless a key is cached or key retrieval succeeds")
	} else if failed > 0 {
		log.Warn().Str("cluster", u.name).Msgf("%d of %d key sources failed", failed, len(u.keyRetrievers))
	} else {
		log.Info().Str("cluster", u.name).Msgf("All %d key sources work", len(u.keyRetrievers))
	}
}

func (u *UnsealAgent) conditionallyUnsealInstances(ctx context.Context) {
	for _, instance := range u.discoverEndpoints(ctx) {
		err := u.conditionalUnsealInstance(ctx, instance)
		if err != nil {
			log.Error().Err(err).Str("cluster", u.name).Msgf("conditionally unseal instance '%s' failed: %v", instance, err)
		}
	}
}

// discoverEndpoints returns the cluster's current instances. If discovery fails, the instances of the last successful
// discovery are returned, so a temporary DNS outage doesn't stop the agent from unsealing known instances.
func (u *UnsealAgent) discoverEndpoints(ctx context.Context) []string {
	endpoints, err := u.discovery.Endpoints(ctx)
	if err != nil {
		EndpointDiscoveryErrors.WithLabelValues(u.name).Inc()
		if len(u.endpoints) == 0 {
			log.Error().Err(err).Str("cluster", u.name).Msg("Could not discover instances and no instances are known")
		} else {
			log.Warn().Err(err).Str("cluster", u.name).Msgf("Could not discover instances, using %d previously known instances", len(u.endpoints))
		}
		return u.endpoints
	}

	for _, instance := range u.endpoints {
		if !slices.Contains(endpoints, instance) {
			log.Info().Str("cluster", u.name).Str("instance", instance).Msg("Instance removed")
			deleteInstanceMetrics(instance)
		}
	}
	for _, instance := range endpoints {
		if !slices.Contains(u.endpoints, instance) {
			log.Info().Str("cluster", u.name).Str("instance", instance).Msg("Instance added")
		}
	}

	u.endpoints = endpoints
	Instances.WithLabelValues(u.name).Set(float64(len(endpoints)))
	return endpoints
}

func (u *UnsealAgent) conditionalUnsealInstance(ctx context.Context, instance string) error {
	log.Debug().Msgf("Checking instance %s", instance)
	LastCheck.WithLabelValues(instance).SetToCurrentTime()

	sealedStatus, err := u.client.GetSealedStatus(ctx, instance)
	if err != nil {
		UnsealErrors.WithLabelValues("sealed_query_failed", instance).Inc()
		return fmt.Errorf("could not detect unseal status: %w", err)
	}

	if !sealedStatus.Sealed {
		log.Debug().Msgf("Instance %s is unsealed", instance)
		UnsealedStatus.WithLabelValues(instance).Set(1)
		return nil
	}

	UnsealedStatus.WithLabelValues(instance).Set(0)
	log.Info().Msgf("Instance %s is sealed, trying to unseal...", instance)
	sealed, rejected, errs := u.submitUnsealKeys(ctx, instance, sealedStatus.Threshold)

	// a cached key may be outdated, e.g. after a rekey. Refresh cached keys and try once more.
	if sealed && rejected && u.invalidateCachedKeys() {
		log.Warn().Str("instance", instance).Msg("Instance rejected unseal keys, refreshing cached keys and trying again")
		if err := u.client.ResetUnseal(ctx, instance); err != nil {
			UnsealErrors.WithLabelValues("unseal_failed", instance).Inc()
			return multierr.Append(errs, fmt.Errorf("could not reset unseal progress: %w", err))
		}

		sealed, _, errs = u.submitUnsealKeys(ctx, instance, sealedStatus.Threshold)
	}

	if sealed {
		return multierr.Append(errs, fmt.Errorf("instance %s is still sealed after submitting unseal keys", instance))
	}

	log.Info().Str("instance", instance).Msg("Instance unsealed successfully")
	UnsealedStatus.WithLabelValues(instance).Set(1)
	if errs != nil {
		log.Warn().Err(errs).Str("instance", instance).Msg("Instance unsealed, but not all key sources work")
	}
	return nil
}

type fetchedKey struct {
	retriever string
	key       string
}

// fetchUnsealKeys retrieves the keys of all retrievers concurrently, so a slow or unavailable key source doesn't delay
// the others. All retrievers are queried, even if fewer keys are needed to reach the threshold, so caches of spare key
// sources are populated and failing key sources are noticed before they are actually needed. Returned keys are in the
// order of the configured retrievers, duplicates are removed.
func (u *UnsealAgent) fetchUnsealKeys(ctx context.Context) ([]fetchedKey, error) {
	keys := make([]string, len(u.keyRetrievers))
	errs := make([]error, len(u.keyRetrievers))
	wg := sync.WaitGroup{}
	for idx, keyRetriever := range u.keyRetrievers {
		wg.Go(func() {
			keys[idx], errs[idx] = keyRetriever.RetrieveUnsealKey(ctx)
		})
	}
	wg.Wait()

	var ret []fetchedKey
	var combinedErrs error
	seen := map[string]string{}
	for idx, keyRetriever := range u.keyRetrievers {
		if errs[idx] != nil {
			UnsealKeyRetrievalErrors.WithLabelValues(u.name, keyRetriever.Name()).Inc()
			combinedErrs = multierr.Append(combinedErrs, fmt.Errorf("retrieving unsealing key failed for %q: %w", keyRetriever.Name(), errs[idx]))
			continue
		}

		if other, found := seen[keys[idx]]; found {
			log.Warn().Str("cluster", u.name).Msgf("Retrievers %q and %q return the same key share, only one of them counts towards the threshold", other, keyRetriever.Name())
			continue
		}
		seen[keys[idx]] = keyRetriever.Name()
		ret = append(ret, fetchedKey{retriever: keyRetriever.Name(), key: keys[idx]})
	}

	return ret, combinedErrs
}

// submitUnsealKeys fetches the keys of all retrievers and submits them to the instance until it's unsealed. It returns
// whether the instance is still sealed and whether it rejected any of the keys.
func (u *UnsealAgent) submitUnsealKeys(ctx context.Context, instance string, threshold int) (bool, bool, error) {
	keys, errs := u.fetchUnsealKeys(ctx)
	if threshold > 0 && len(keys) < threshold {
		log.Warn().Str("instance", instance).Msgf("Only %d of %d required unseal keys available, the threshold can't be reached without additional keys", len(keys), threshold)
	}

	sealed := true
	rejected := false
	for _, key := range keys {
		status, err := u.client.Unseal(ctx, instance, key.key)
		if err != nil {
			rejected = rejected || errors.Is(err, vault.ErrUnsealKeyRejected)
			UnsealErrors.WithLabelValues("unseal_failed", instance).Inc()
			errs = multierr.Append(errs, fmt.Errorf("unsealing failed: %w", err))
			continue
		}

		log.Info().Str("instance", instance).Str("retriever", key.retriever).Msgf("Submitted unseal key, progress %d/%d", status.Progress, status.Threshold)
		if !status.Sealed {
			sealed = false
			break
		}
	}

	return sealed, rejected, errs
}

// invalidateCachedKeys discards all cached keys of this cluster. It returns whether any retriever caches keys at all.
// As Vault does not tell which key share is wrong, all cached keys are discarded.
func (u *UnsealAgent) invalidateCachedKeys() bool {
	invalidated := false
	for _, keyRetriever := range u.keyRetrievers {
		if cachingRetriever, ok := keyRetriever.(unsealing.CachingUnsealKeyRetriever); ok {
			cachingRetriever.Invalidate()
			invalidated = true
		}
	}
	return invalidated
}
