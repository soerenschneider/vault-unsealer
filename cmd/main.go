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
	"github.com/soerenschneider/vault-unsealer/internal/unsealing"
	"github.com/soerenschneider/vault-unsealer/pkg/vault"
	"github.com/soerenschneider/vault-unsealer/pkg/vault/auth"
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
	config             config.UnsealConfig
	unsealKeyRetriever unsealing.UnsealKeyRetriever
	vaultClient        vault.Client
	unsealAgent        *internal.UnsealAgent
}

func main() {
	parseFlags()

	configureLogging()
	configureHttpClient()

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

	if u.unsealKeyRetriever, err = u.buildKeyRetriever(clusterConf); err != nil {
		log.Fatal().Err(err).Msg("could not build key retriever")
	}

	if u.unsealAgent, err = internal.NewUnsealAgent(clusterConf, u.vaultClient, u.unsealKeyRetriever); err != nil {
		log.Fatal().Err(err).Msg("could not build unseal agent")
	}
}

func (u *vaultUnsealer) buildVaultClient() (vault.Client, error) {
	return vault.NewSimpleVaultClient(defaultHttpClient)
}

func (u *vaultUnsealer) buildKeyRetriever(clusterConf config.ClusterConfig) (unsealing.UnsealKeyRetriever, error) {
	conf, err := config.GetRetrieveConfig(clusterConf)
	if err != nil {
		return nil, err
	}

	var retriever unsealing.UnsealKeyRetriever
	if conf.Kv2Config != nil {
		retriever, err = u.buildKv2Retriever(conf)
	} else if conf.TransitConfig != nil {
		retriever, err = u.buildTransitRetriever(conf)
	} else if conf.StaticConfig != nil {
		retriever, err = u.buildStaticRetriever(conf)
	} else {
		return nil, errors.New("invalid unseal config")
	}

	if err != nil {
		return nil, err
	}

	if clusterConf.CacheUnsealKey {
		return unsealing.NewCachedUnsealKeyRetriever(retriever)
	}

	return retriever, nil
}

func (u *vaultUnsealer) buildKv2Retriever(conf *config.VaultRetrieveConfig) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building Vault KV2 unseal key retriever")
	auth, err := auth.BuildVaultAuth(conf.TransitConfig.VaultAuthType, conf.TransitConfig.VaultAuthConfig, conf.TransitConfig.VaultEndpoint, defaultHttpClient)
	if err != nil {
		return nil, err
	}

	return unsealing.NewVaultKvRetriever(u.vaultClient.(unsealing.VaultKv2), auth, *conf.Kv2Config)
}

func (u *vaultUnsealer) buildStaticRetriever(conf *config.VaultRetrieveConfig) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building static unseal key receiver")
	return unsealing.NewStaticUnsealKeyRetriever(conf.StaticConfig.UnsealKey)
}

func (u *vaultUnsealer) buildTransitRetriever(conf *config.VaultRetrieveConfig) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building Vault transit impl to receive unseal keys")
	auth, err := auth.BuildVaultAuth(conf.TransitConfig.VaultAuthType, conf.TransitConfig.VaultAuthConfig, conf.TransitConfig.VaultEndpoint, defaultHttpClient)
	if err != nil {
		return nil, err
	}

	return unsealing.NewVaultTransitReceiver(u.vaultClient.(unsealing.VaultTransit), auth, conf.TransitConfig)
}
