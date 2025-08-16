package unseal

type VaultStaticConfig struct {
	UnsealKey string `yaml:"unseal_key"`

	WrappedConfig
}
