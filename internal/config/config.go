package config

import (
	"os"

	"github.com/go-playground/validator/v10"
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
	Endpoints            []string       `yaml:"endpoints" validate:"required"`
	VerifyClusterId      string         `yaml:"verify_cluster_id,omitempty"`
	CacheUnsealKey       bool           `yaml:"cache_unseal_key"`
	CheckIntervalSeconds int            `yaml:"check_interval_s" validate:"gte=60,lte=3600"`
	RetrieveConfig       map[string]any `yaml:"unseal_key_config"`
	RetrieveImpl         string         `yaml:"unseal_key_impl" validate:"oneof=vault-transit vault-kv2 static"`
}

type VaultRetrieveConfig struct {
	TransitConfig *unseal.VaultTransitConfig
	StaticConfig  *unseal.VaultStaticConfig
	Kv2Config     *unseal.VaultKv2Config
}

func GetRetrieveConfig(clusterConf ClusterConfig) (*VaultRetrieveConfig, error) {
	conf := &VaultRetrieveConfig{}
	switch clusterConf.RetrieveImpl {
	case "vault-transit":
		parsedConf, err := UnmarshalGeneric[unseal.VaultTransitConfig](clusterConf.RetrieveConfig)
		if err != nil {
			return nil, err
		}
		conf.TransitConfig = parsedConf
	case "vault-kv2":
		parsedConf, err := UnmarshalGeneric[unseal.VaultKv2Config](clusterConf.RetrieveConfig)
		if err != nil {
			return nil, err
		}
		conf.Kv2Config = parsedConf
	case "static":
		parsedConf, err := UnmarshalGeneric[unseal.VaultStaticConfig](clusterConf.RetrieveConfig)
		if err != nil {
			return nil, err
		}
		conf.StaticConfig = parsedConf
	}

	return conf, nil
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
