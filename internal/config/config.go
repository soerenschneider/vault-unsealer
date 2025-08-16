package config

import (
	"fmt"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
	"github.com/soerenschneider/vault-unsealer/internal/config/unseal"
	"gopkg.in/yaml.v3"
)

var validate = validator.New()

const (
	defaultPrometheusAddr = ":9132"
)

func NewDefaultConfig() UnsealConfig {
	return UnsealConfig{
		PrometheusAddr: defaultPrometheusAddr,
	}
}

type UnsealConfig struct {
	Clusters       []ClusterConfig `yaml:"clusters"`
	PrometheusAddr string          `yaml:"prometheus_addr,omitempty"`
}

type ClusterConfig struct {
	Endpoints            []string         `yaml:"endpoints" validate:"required"`
	VerifyClusterId      string           `yaml:"verify_cluster_id,omitempty"`
	CacheUnsealKey       bool             `yaml:"cache_unseal_key"`
	CheckIntervalSeconds int              `yaml:"check_interval_s" validate:"gte=60,lte=3600"`
	RetrieveConfig       []map[string]any `yaml:"unseal_key_config"`
}

type VaultRetrieveConfig struct {
	TransitConfig *unseal.VaultTransitConfig
	StaticConfig  *unseal.VaultStaticConfig
	Kv2Config     *unseal.VaultKv2Config
	AwsKmsConfig  *unseal.AwsKmsConfig
}

func GetRetrieveConfig(clusterConf ClusterConfig) ([]VaultRetrieveConfig, error) {
	ret := make([]VaultRetrieveConfig, len(clusterConf.RetrieveConfig))

	for idx, confEntry := range clusterConf.RetrieveConfig {
		retrieveImpl, ok := confEntry["impl"]
		if !ok {
			return nil, fmt.Errorf("entry %d is missing required attribute 'impl'", idx)
		}
		switch retrieveImpl {
		case "aws-kms":
			parsedConf := MustUnmarshalGeneric[unseal.AwsKmsConfig](confEntry)
			ret[idx].AwsKmsConfig = parsedConf
		case "vault-transit":
			parsedConf := MustUnmarshalGeneric[unseal.VaultTransitConfig](confEntry)
			ret[idx].TransitConfig = parsedConf
		case "vault-kv2":
			parsedConf := MustUnmarshalGeneric[unseal.VaultKv2Config](confEntry)
			ret[idx].Kv2Config = parsedConf
		case "static":
			parsedConf := MustUnmarshalGeneric[unseal.VaultStaticConfig](confEntry)
			ret[idx].StaticConfig = parsedConf
		}
	}

	return ret, nil
}

func MustUnmarshalGeneric[T any](data map[string]any) *T {
	ret, err := UnmarshalGeneric[T](data)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to unmarshal config")
	}
	return ret
}

func UnmarshalGeneric[T any](data map[string]any) (*T, error) {
	var ret T

	marshalled, err := yaml.Marshal(data)
	if err != nil {
		return nil, err
	}

	return &ret, yaml.Unmarshal(marshalled, &ret)
}

func Validate(conf *UnsealConfig) error {
	return validate.Struct(conf)
}

func ReadConfig(file string) (*UnsealConfig, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	conf := UnsealConfig{}
	err = yaml.Unmarshal(data, &conf)
	return &conf, err
}
