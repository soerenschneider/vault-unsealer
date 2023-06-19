package unseal

import "os"

type VaultTransitConfig struct {
	VaultAuthType              string         `json:"vault_auth_type" validate:"required,oneof implicit,token,approle"`
	VaultAuthConfig            map[string]any `json:"vault_auth_config"`
	VaultEndpoint              string         `json:"vault_endpoint" validate:"required,http_url"`
	VaultTransitMountPath      string         `json:"vault_transit_mount_path"`
	VaultTransitKeyName        string         `json:"vault_transit_key_name" validate:"required"`
	VaultTransitCiphertextFile string         `json:"vault_transit_ciphertext_file" validate:"file"`
	VaultTransitCiphertext     string         `json:"vault_transit_ciphertext"`
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
