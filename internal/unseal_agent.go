package internal

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/soerenschneider/vault-unsealer/internal/config"
	"github.com/soerenschneider/vault-unsealer/internal/unsealing"
	"github.com/soerenschneider/vault-unsealer/pkg/vault"
)

type UnsealAgent struct {
	keyRetrievers []unsealing.UnsealKeyRetriever
	client        vault.Client
	conf          config.ClusterConfig
}

func NewUnsealAgent(conf config.ClusterConfig, client vault.Client, keyRetrievers []unsealing.UnsealKeyRetriever) (*UnsealAgent, error) {
	if client == nil {
		return nil, errors.New("no vault client provided")
	}

	if len(keyRetrievers) == 0 {
		return nil, errors.New("no key retrievers provided")
	}

	return &UnsealAgent{
		client:        client,
		keyRetrievers: keyRetrievers,
		conf:          conf,
	}, nil
}

func (u *UnsealAgent) Run(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Add(1)
	defer wg.Done()

	for _, keyRetriever := range u.keyRetrievers {
		log.Info().Str("Retriever", keyRetriever.Name()).Msg("Checking if receiving unseal key works...")
		// Test whether key retrieval works before we actually need it
		_, err := keyRetriever.RetrieveUnsealKey(ctx)
		if err != nil {
			log.Error().Err(err).Msg("Could not retrieve unseal key")
			UnsealKeyRetrievalErrors.WithLabelValues(keyRetriever.Name()).Inc()
			return err
		}
		log.Info().Msg("Received unseal key")
	}

	u.conditionallyUnsealInstances(ctx)

	ticker := time.NewTicker(time.Duration(u.conf.CheckIntervalSeconds) * time.Second)
	for {
		select {
		case <-ctx.Done():
			ticker.Stop()
			return nil
		case <-ticker.C:
			u.conditionallyUnsealInstances(ctx)
		}
	}
}

func (u *UnsealAgent) conditionallyUnsealInstances(ctx context.Context) {
	for _, instance := range u.conf.Endpoints {
		err := u.conditionalUnsealInstance(ctx, instance)
		if err != nil {
			log.Error().Err(err).Msgf("conditionally unseal instance '%s' failed: %v", instance, err)
		}
	}
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

	log.Info().Msgf("Instance %s is sealed, trying to unseal...", instance)
	UnsealedStatus.WithLabelValues(instance).Set(0)
	for _, keyRetriever := range u.keyRetrievers {
		unsealKey, err := keyRetriever.RetrieveUnsealKey(ctx)
		if err != nil {
			UnsealKeyRetrievalErrors.WithLabelValues(keyRetriever.Name()).Inc()
			return fmt.Errorf("retrieving unsealing key failed: %v", err)
		}

		err = u.client.Unseal(ctx, instance, unsealKey)
		if err != nil {
			UnsealErrors.WithLabelValues("unseal_failed", instance).Inc()
			return err
		}
	}

	return nil
}
