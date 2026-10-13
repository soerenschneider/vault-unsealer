package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/rs/zerolog/log"
	"github.com/soerenschneider/vault-unsealer/v2/internal/config/unseal"
	"gopkg.in/yaml.v3"
)

var validate = validator.New()

const (
	defaultPrometheusAddr          = ":9132"
	defaultKeyCheckIntervalSeconds = 3600 * 24
	defaultSrvScheme               = "https"
)

func NewDefaultConfig() UnsealConfig {
	return UnsealConfig{
		PrometheusAddr: defaultPrometheusAddr,
	}
}

type UnsealConfig struct {
	Clusters       []ClusterConfig `yaml:"clusters" validate:"required,min=1,dive"`
	PrometheusAddr string          `yaml:"prometheus_addr,omitempty"`
}

type ClusterConfig struct {
	Name                    string           `yaml:"name,omitempty"`
	Endpoints               []string         `yaml:"endpoints" validate:"omitempty,min=1"`
	EndpointsSrv            *SrvConfig       `yaml:"endpoints_srv,omitempty"`
	CheckIntervalSeconds    int              `yaml:"check_interval_s" validate:"gte=60,lte=3600"`
	KeyCheckIntervalSeconds int              `yaml:"key_check_interval_s" validate:"omitempty,gte=60,lte=86400"`
	RetrieveConfig          []map[string]any `yaml:"unseal_key_config"`
}

// SrvConfig configures the discovery of a cluster's instances via a DNS SRV record.
type SrvConfig struct {
	Record string `yaml:"record" validate:"required"`
	Scheme string `yaml:"scheme,omitempty" validate:"omitempty,oneof=http https"`
}

// SchemeOrDefault returns the URL scheme used for the discovered instances.
func (c SrvConfig) SchemeOrDefault() string {
	if c.Scheme == "" {
		return defaultSrvScheme
	}
	return c.Scheme
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
	if err := validate.Struct(conf); err != nil {
		return err
	}

	names := map[string]bool{}
	for idx, cluster := range conf.Clusters {
		name := cluster.NameOrDefault(idx)
		if cluster.Endpoints == nil && cluster.EndpointsSrv == nil {
			return fmt.Errorf("cluster %q: either endpoints or endpoints_srv must be set", name)
		}
		if cluster.Endpoints != nil && cluster.EndpointsSrv != nil {
			return fmt.Errorf("cluster %q: endpoints and endpoints_srv are mutually exclusive", name)
		}
		if names[name] {
			return fmt.Errorf("cluster name %q is not unique", name)
		}
		names[name] = true
	}

	return nil
}

// KeyCheckIntervalOrDefault returns the interval in which all key sources are checked.
func (c ClusterConfig) KeyCheckIntervalOrDefault() time.Duration {
	if c.KeyCheckIntervalSeconds == 0 {
		return defaultKeyCheckIntervalSeconds * time.Second
	}
	return time.Duration(c.KeyCheckIntervalSeconds) * time.Second
}

// NameOrDefault returns the cluster's name, or its index in the list of clusters if no name is set.
func (c ClusterConfig) NameOrDefault(idx int) string {
	if len(c.Name) == 0 {
		return strconv.Itoa(idx)
	}
	return c.Name
}

func ReadConfig(file string) (*UnsealConfig, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	conf := NewDefaultConfig()
	err = yaml.Unmarshal(data, &conf)
	return &conf, err
}
