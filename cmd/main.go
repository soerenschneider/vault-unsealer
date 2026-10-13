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
	"github.com/soerenschneider/vault-unsealer/v2/internal"
	"github.com/soerenschneider/vault-unsealer/v2/internal/config"
	"github.com/soerenschneider/vault-unsealer/v2/internal/config/unseal"
	vault_auth "github.com/soerenschneider/vault-unsealer/v2/internal/config/vault"
	"github.com/soerenschneider/vault-unsealer/v2/internal/unsealing"
	"github.com/soerenschneider/vault-unsealer/v2/internal/vault"
	"github.com/soerenschneider/vault-unsealer/v2/internal/vault/auth"
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
	config       config.UnsealConfig
	vaultClient  vault.Client
	authMethods  []vault.AuthMethod
	unsealAgents []*internal.UnsealAgent
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
	unsealer.buildDependencies()

	internal.UptimeMetric.SetToCurrentTime()
	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithCancel(context.Background())
	for _, agent := range unsealer.unsealAgents {
		wg.Go(func() {
			agent.Run(ctx)
		})
	}

	wg.Go(func() {
		if err := internal.StartMetricsServer(ctx, unsealer.config.PrometheusAddr); err != nil {
			log.Fatal().Err(err).Msg("prometheus metrics server failed")
		}
	})

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
	unsealer.cleanup()
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
	defaultHttpClient = buildHttpClient()
}

func buildHttpClient() *http.Client {
	client := retryablehttp.NewClient()
	client.RetryMax = 5
	// timeout per attempt, not for the whole request including retries
	client.HTTPClient.Timeout = 3 * time.Second
	client.Logger = &retryableHttpLogger{}
	// return the last response instead of a generic error once retries are exhausted, so callers can inspect it
	client.ErrorHandler = retryablehttp.PassthroughErrorHandler
	return client.StandardClient()
}

// retryableHttpLogger adapts zerolog to retryablehttp's LeveledLogger interface.
type retryableHttpLogger struct{}

// Error is called for each failed attempt, the final error is logged by the caller.
func (l *retryableHttpLogger) Error(msg string, keysAndValues ...any) {
	log.Warn().Fields(keysAndValues).Msg(msg)
}

func (l *retryableHttpLogger) Warn(msg string, keysAndValues ...any) {
	log.Warn().Fields(keysAndValues).Msg(msg)
}

func (l *retryableHttpLogger) Info(msg string, keysAndValues ...any) {
	log.Info().Fields(keysAndValues).Msg(msg)
}

func (l *retryableHttpLogger) Debug(msg string, keysAndValues ...any) {
	log.Debug().Fields(keysAndValues).Msg(msg)
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

func (u *vaultUnsealer) buildDependencies() {
	var err error
	if u.vaultClient, err = u.buildVaultClient(); err != nil {
		log.Fatal().Err(err).Msg("could not build vault client")
	}

	for idx, clusterConf := range u.config.Clusters {
		name := clusterConf.NameOrDefault(idx)

		retrievers, err := u.buildKeyRetriever(clusterConf)
		if err != nil {
			log.Fatal().Err(err).Str("cluster", name).Msg("could not build key retriever")
		}

		log.Info().Str("cluster", name).Msg("Building agent")
		agent, err := internal.NewUnsealAgent(name, clusterConf, u.vaultClient, retrievers)
		if err != nil {
			log.Fatal().Err(err).Str("cluster", name).Msg("could not build unseal agent")
		}
		u.unsealAgents = append(u.unsealAgents, agent)
	}
}

// cleanup revokes all tokens that have been issued to vault-unsealer.
func (u *vaultUnsealer) cleanup() {
	for _, authMethod := range u.authMethods {
		if err := authMethod.Cleanup(defaultHttpClient); err != nil {
			log.Warn().Err(err).Msg("could not clean up vault auth")
		}
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
	retriever, err := unsealing.NewAwsKmsKeyRetriever(conf)
	if err != nil {
		return nil, fmt.Errorf("could not build aws-kms retriever: %w", err)
	}

	return wrapRetriever(retriever, conf.MustGetWrappedPassphrase(), conf.Cache)
}

func (u *vaultUnsealer) buildKv2Retriever(conf *unseal.VaultKv2Config) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building Vault KV2 unseal key retriever")
	auth, err := BuildVaultAuth(conf.VaultAuthType, conf.VaultAuthConfig, conf.VaultEndpoint, defaultHttpClient)
	if err != nil {
		return nil, err
	}
	u.authMethods = append(u.authMethods, auth)

	retriever, err := unsealing.NewVaultKvRetriever(u.vaultClient.(unsealing.VaultKv2), auth, *conf)
	if err != nil {
		return nil, fmt.Errorf("could not build vault-kv retriever: %w", err)
	}

	return wrapRetriever(retriever, conf.MustGetWrappedPassphrase(), conf.Cache)
}

func (u *vaultUnsealer) buildStaticRetriever(conf *unseal.VaultStaticConfig) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building static unseal key receiver")
	retriever, err := unsealing.NewStaticUnsealKeyRetriever(conf.UnsealKey)
	if err != nil {
		return nil, fmt.Errorf("could not build static retriever: %w", err)
	}

	return wrapRetriever(retriever, conf.MustGetWrappedPassphrase(), conf.Cache)
}

func (u *vaultUnsealer) buildTransitRetriever(conf *unseal.VaultTransitConfig) (unsealing.UnsealKeyRetriever, error) {
	log.Info().Msg("Building Vault transit impl to receive unseal keys")
	auth, err := BuildVaultAuth(conf.VaultAuthType, conf.VaultAuthConfig, conf.VaultEndpoint, defaultHttpClient)
	if err != nil {
		return nil, err
	}
	u.authMethods = append(u.authMethods, auth)

	retriever, err := unsealing.NewVaultTransitReceiver(u.vaultClient.(unsealing.VaultTransit), auth, conf)
	if err != nil {
		return nil, fmt.Errorf("could not build vault-transit retriever: %w", err)
	}

	return wrapRetriever(retriever, conf.MustGetWrappedPassphrase(), conf.Cache)
}

func wrapRetriever(retriever unsealing.UnsealKeyRetriever, wrappedPassphrase string, cache bool) (unsealing.UnsealKeyRetriever, error) {
	if retriever == nil {
		return nil, errors.New("can not wrap retriever: nil retriever provided")
	}

	var err error
	if wrappedPassphrase != "" {
		log.Info().Str("retriever", retriever.Name()).Msg("Wrapping unseal key with age")
		retrieverName := retriever.Name()
		retriever, err = unsealing.NewAgeWrapper(wrappedPassphrase, retriever)
		if err != nil {
			return nil, fmt.Errorf("could not build age wrapper around %s retriever: %w", retrieverName, err)
		}
	}

	if !cache {
		return retriever, nil
	}

	log.Info().Str("retriever", retriever.Name()).Msg("Caching results for retriever")
	retriever, err = unsealing.NewCachedUnsealKeyRetriever(retriever)
	if err != nil {
		return nil, fmt.Errorf("could not build cache wrapper around %s retriever: %w", retriever.Name(), err)
	}

	return retriever, nil
}

func BuildVaultAuth(authType string, authData map[string]any, vaultEndpoint string, httpClient *http.Client) (vault.AuthMethod, error) {
	switch authType {
	case "implicit":
		log.Info().Msg("Building 'implicit' vault auth implementation")
		return auth.NewTokenImplicitAuth("~/.vault-token"), nil
	case "token":
		log.Info().Msg("Building 'token' vault auth implementation")
		conf, err := config.UnmarshalGeneric[vault_auth.AuthTokenConfig](authData)
		if err != nil {
			return nil, err
		}
		return auth.NewTokenAuth(conf.Token)
	case "approle":
		log.Info().Msg("Building 'approle' vault auth implementation")
		conf, err := config.UnmarshalGeneric[vault_auth.AuthApproleConfig](authData)
		if err != nil {
			return nil, err
		}
		return auth.NewAppRoleAuth(vaultEndpoint, *conf)
	default:
		return nil, fmt.Errorf("unknown vault auth implementation: %s", authType)
	}
}
