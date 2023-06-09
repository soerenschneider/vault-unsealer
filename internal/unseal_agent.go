package internal

import (
	"context"
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/soerenschneider/vault-unsealer/internal/config"
	"github.com/soerenschneider/vault-unsealer/internal/unsealing"
	"github.com/soerenschneider/vault-unsealer/pkg/vault"
	"sync"
	"time"
)

type UnsealAgent struct {
	keyRetriever unsealing.UnsealKeyRetriever
	client       vault.Client
	conf         config.ClusterConfig
}

func NewUnsealAgent(conf config.ClusterConfig, client vault.Client, keyRetriever unsealing.UnsealKeyRetriever) (*UnsealAgent, error) {
	if client == nil {
		return nil, errors.New("no vault client provided")
	}

	if keyRetriever == nil {
		return nil, errors.New("empty key retriever provided")
	}

	return &UnsealAgent{
		client:       client,
		keyRetriever: keyRetriever,
		conf:         conf,
	}, nil
}

func (u *UnsealAgent) Run(ctx context.Context, wg *sync.WaitGroup) error {
	wg.Add(1)
	defer wg.Done()

	log.Info().Msg("Checking if receiving unseal key works...")
	// Test whether key retrieval works before we actually need it
	_, err := u.keyRetriever.RetrieveUnsealKey(ctx)
	if err != nil {
		log.Error().Err(err).Msg("Could not retrieve unseal key")
		UnsealKeyRetrievalErrors.Inc()
		return err
	}
	log.Info().Msg("Received unseal key")

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
	unsealKey, err := u.keyRetriever.RetrieveUnsealKey(ctx)
	if err != nil {
		UnsealKeyRetrievalErrors.Inc()
		return fmt.Errorf("retrieving unsealing key failed: %v", err)
	}

	err = u.client.Unseal(ctx, instance, unsealKey)
	if err != nil {
		UnsealErrors.WithLabelValues("unseal_failed", instance).Inc()
		return err
	}

	return nil
}
