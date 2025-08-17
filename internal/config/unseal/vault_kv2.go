package unseal

const (
	defaultMountPath = "secret"
	defaultSecretKey = "unseal_key"
)

type VaultKv2Config struct {
	VaultAuthType      string         `yaml:"vault_auth_type" validate:"required,oneof implicit,token,approle"`
	VaultAuthConfig    map[string]any `yaml:"vault_auth_config" validate:"required"`
	VaultEndpoint      string         `yaml:"vault_endpoint" validate:"required,http_url"`
	VaultKv2MountPath  string         `yaml:"vault_kv2_mount_path"`
	VaultKv2SecretPath string         `yaml:"vault_kv2_secret_path"`
	VaultKv2SecretKey  string         `yaml:"vault_kv2_secret_key"`

	WrappedConfig `yaml:",inline"`
}

func (c *VaultKv2Config) MountPathOrDefault() string {
	if len(c.VaultKv2MountPath) == 0 {
		return defaultMountPath
	}

	return c.VaultKv2MountPath
}

func (c *VaultKv2Config) SecretKeyOrDefault() string {
	if len(c.VaultKv2SecretKey) == 0 {
		return defaultSecretKey
	}

	return c.VaultKv2SecretKey
}
