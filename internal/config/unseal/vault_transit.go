package unseal

import "os"

type VaultTransitConfig struct {
	VaultAuthType              string         `yaml:"vault_auth_type" validate:"required,oneof implicit,token,approle"`
	VaultAuthConfig            map[string]any `yaml:"vault_auth_config"`
	VaultEndpoint              string         `yaml:"vault_endpoint" validate:"required,http_url"`
	VaultTransitMountPath      string         `yaml:"vault_transit_mount_path"`
	VaultTransitKeyName        string         `yaml:"vault_transit_key_name" validate:"required"`
	VaultTransitCiphertextFile string         `yaml:"vault_transit_ciphertext_file" validate:"file"`
	VaultTransitCiphertext     string         `yaml:"vault_transit_ciphertext"`

	WrappedConfig
}

func (c *VaultTransitConfig) GetCiphertext() (string, error) {
	if len(c.VaultTransitCiphertextFile) == 0 {
		return c.VaultTransitCiphertext, nil
	}

	ciphertext, err := os.ReadFile(c.VaultTransitCiphertextFile)
	if err != nil {
		return "", err
	}

	return string(ciphertext), nil
}
