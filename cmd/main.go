package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog"
	log "github.com/rs/zerolog/log"
	"github.com/soerenschneider/vault-unsealer/internal"
	"github.com/soerenschneider/vault-unsealer/internal/config"
	"github.com/soerenschneider/vault-unsealer/internal/config/unseal"
	"github.com/soerenschneider/vault-unsealer/internal/unsealing"
	"github.com/soerenschneider/vault-unsealer/pkg/vault"
	"github.com/soerenschneider/vault-unsealer/pkg/vault/auth"
	"go.uber.org/multierr"
)

const (
	defaultConfigFile = "/etc/vault-unsealer.json"
)

var (
	configFile        string
	debug             bool
	defaultHttpClient *http.Client
	version           bool
)

type vaultUnsealer struct {
	config              config.UnsealConfig
	unsealKeyRetrievers []unsealing.UnsealKeyRetriever
	vaultClient         vault.Client
	unsealAgent         *internal.UnsealAgent
}

func main() {
	parseFlags()

	configureLogging()
	configureHttpClient()

	log.Info().Msgf("vault-unsealer %s (%s)", internal.BuildVersion, internal.CommitHash)
	internal.VersionMetric.WithLabelValues(internal.BuildVersion, internal.CommitHash).Set(1)

	unsealer := &vaultUnsealer{}
	log.Info().Msg("Building config objects")
	unsealer.retrieveConfig()

	log.Info().Msg("Building dependencies")
	unsealer.buildDependencies(unsealer.config.Clusters[0])

	internal.UptimeMetric.SetToCurrentTime()
	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		log.Info().Msg("Starting agent")
		err := unsealer.unsealAgent.Run(ctx, wg)
		if err != nil {
			log.Fatal().Err(err).Msg("error running agent")
		}
	}()

	go func() {
		err := internal.StartMetricsServer(unsealer.config.PrometheusAddr)
		if err != nil {
			log.Fatal().Err(err).Msg("could not start prometheus metrics server")
		}
	}()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	<-sigc
	log.Info().Msg("Received shutdown signal")
	cancel()
	log.Info().Msg("Waiting for waitgroups")
	wg.Wait()
	log.Info().Msg("Done, bye")
}

func parseFlags() {
	flag.StringVar(&configFile, "conf", defaultConfigFile, "config file location")
	flag.BoolVar(&debug, "debug", false, "print debug logs")
	flag.BoolVar(&version, "version", false, "print version and exit")
	flag.Parse()

	if version {
		fmt.Printf("vault-unsealer %s (%s)\n", internal.BuildVersion, internal.CommitHash)
		os.Exit(0)
	}
}

func configureHttpClient() {
	client := retryablehttp.NewClient()
	client.RetryMax = 5
	defaultHttpClient = client.HTTPClient
	defaultHttpClient.Timeout = 3 * time.Second
}

func configureLogging() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

func (u *vaultUnsealer) retrieveConfig() {
	conf, err := config.ReadConfig(configFile)
	if err != nil {
		log.Fatal().Err(err).Msg("could not read config")
	}
	err = config.Validate(conf)
	if err != nil {
		log.Fatal().Err(err).Msg("could not validate config")
	}

	u.config = *conf
}

func (u *vaultUnsealer) buildDependencies(clusterConf config.ClusterConfig) {
	var err error
	if u.vaultClient, err = u.buildVaultClient(); err != nil {
		log.Fatal().Err(err).Msg("could not build vault client")
	}

	if u.unsealKeyRetrievers, err = u.buildKeyRetriever(clusterConf); err != nil {
		log.Fatal().Err(err).Msg("could not build key retriever")
	}

	if u.unsealAgent, err = internal.NewUnsealAgent(clusterConf, u.vaultClient, u.unsealKeyRetrievers); err != nil {
		log.Fatal().Err(err).Msg("could not build unseal agent")
	}
}

func (u *vaultUnsealer) buildVaultClient() (vault.Client, error) {
	return vault.NewSimpleVaultClient(defaultHttpClient)
}

func (u *vaultUnsealer) buildKeyRetriever(clusterConf config.ClusterConfig) ([]unsealing.UnsealKeyRetriever, error) {
	configs, err := config.GetRetrieveConfig(clusterConf)
	if err != nil {
		return nil, err
	}

	var retrievers = make([]unsealing.UnsealKeyRetriever, len(configs))
	var errs error
	for idx, config := range configs {
		if config.AwsKmsConfig != nil {
			retrievers[idx], err = u.buildAwsKmsRetriever(config.AwsKmsConfig)
		} else if config.Kv2Config != nil {
			retrievers[idx], err = u.buildKv2Retriever(config.Kv2Config)
		} else if config.TransitConfig != nil {
			retrievers[idx], err = u.buildTransitRetriever(config.TransitConfig)
		} else if config.StaticConfig != nil {
			retrievers[idx], err = u.buildStaticRetriever(config.StaticConfig)
		} else {
			return nil, errors.New("no config provided")
		}

		if err != nil {
			errs = multierr.Append(errs, err)
		}
	}

	return retrievers, errs
}

func (u *vaultUnsealer) buildAwsKmsRetriever(conf *unseal.AwsKmsConfig) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building AWS KMS unseal key retriever")
	awsKmsRetriever, err := unsealing.NewAwsKmsKeyRetriever(conf)
	if err != nil {
		return nil, fmt.Errorf("could not build aws-kms retriever: %w", err)
	}

	return wrapRetriever(awsKmsRetriever, conf.WrappedPassphrase, conf.Cache)
}

func (u *vaultUnsealer) buildKv2Retriever(conf *unseal.VaultKv2Config) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building Vault KV2 unseal key retriever")
	auth, err := auth.BuildVaultAuth(conf.VaultAuthType, conf.VaultAuthConfig, conf.VaultEndpoint, defaultHttpClient)
	if err != nil {
		return nil, err
	}

	retriever, err := unsealing.NewVaultKvRetriever(u.vaultClient.(unsealing.VaultKv2), auth, *conf)
	if err != nil {
		return nil, fmt.Errorf("could not build vault-kv retriever: %w", err)
	}

	return wrapRetriever(retriever, conf.WrappedPassphrase, conf.Cache)
}

func (u *vaultUnsealer) buildStaticRetriever(conf *unseal.VaultStaticConfig) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building static unseal key receiver")
	retriever, err := unsealing.NewStaticUnsealKeyRetriever(conf.UnsealKey)
	if err != nil {
		return nil, fmt.Errorf("could not build static retriever: %w", err)
	}

	return wrapRetriever(retriever, conf.WrappedPassphrase, false)
}

func (u *vaultUnsealer) buildTransitRetriever(conf *unseal.VaultTransitConfig) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building Vault transit impl to receive unseal keys")
	auth, err := auth.BuildVaultAuth(conf.VaultAuthType, conf.VaultAuthConfig, conf.VaultEndpoint, defaultHttpClient)
	if err != nil {
		return nil, err
	}

	retriever, err := unsealing.NewVaultTransitReceiver(u.vaultClient.(unsealing.VaultTransit), auth, conf)
	if err != nil {
		return nil, fmt.Errorf("could not build vault-transit retriever: %w", err)
	}

	return wrapRetriever(retriever, conf.WrappedPassphrase, false)
}

func wrapRetriever(retriever unsealing.UnsealKeyRetriever, wrappedPassphrase string, cache bool) (unsealing.UnsealKeyRetriever, error) {
	if retriever == nil {
		return nil, errors.New("can not wrap retriever: nil retriever provided")
	}

	var err error
	if wrappedPassphrase != "" {
		retriever, err = unsealing.NewAgeWrapper(wrappedPassphrase, retriever)
		if err != nil {
			return nil, fmt.Errorf("could not build age wrapper around %s retriever: %w", retriever.Name(), err)
		}
	}

	if !cache {
		return retriever, nil
	}

	retriever, err = unsealing.NewCachedUnsealKeyRetriever(retriever)
	if err != nil {
		return nil, fmt.Errorf("could not build cache wrapper around %s retriever: %w", retriever.Name(), err)
	}

	return retriever, nil
}
