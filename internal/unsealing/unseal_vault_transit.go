package unsealing

import (
	"context"
	"errors"

	"github.com/go-playground/validator/v10"
	"github.com/soerenschneider/vault-unsealer/internal/config/unseal"
	"github.com/soerenschneider/vault-unsealer/pkg/vault"
)

type VaultTransit interface {
	Decrypt(ctx context.Context, auth vault.AuthMethod, instance string, req vault.TransitDecryptRequest) (string, error)
}

type VaultTransitReceiver struct {
	cipherText               string           `validate:"required"`
	transitClient            VaultTransit     `validate:"required"`
	transitMountPath         string           `validate:"required"`
	transitEncryptionKeyName string           `validate:"required"`
	vaultEndpoint            string           `validate:"required"`
	authMethod               vault.AuthMethod `validate:"required"`
}

func NewVaultTransitReceiver(client VaultTransit, auth vault.AuthMethod, config *unseal.VaultTransitConfig) (*VaultTransitReceiver, error) {
	if client == nil {
		return nil, errors.New("empty client provided")
	}

	if auth == nil {
		return nil, errors.New("empty auth provided")
	}

	if config == nil {
		return nil, errors.New("empty config provided")
	}

	ciphertext, err := config.GetCiphertext()
	if err != nil {
		return nil, err
	}

	transit := &VaultTransitReceiver{
		vaultEndpoint:            config.VaultEndpoint,
		transitEncryptionKeyName: config.VaultTransitKeyName,
		transitMountPath:         config.VaultTransitMountPath,
		cipherText:               ciphertext,
		transitClient:            client,
		authMethod:               auth,
	}

	return transit, validator.New().Struct(transit)
}

func (r *VaultTransitReceiver) RetrieveUnsealKey(ctx context.Context) (string, error) {
	req := vault.TransitDecryptRequest{
		MountPath:         r.transitMountPath,
		EncryptionKeyName: r.transitEncryptionKeyName,
		Ciphertext:        r.cipherText,
	}

	return r.transitClient.Decrypt(ctx, r.authMethod, r.vaultEndpoint, req)
}

func (r *VaultTransitReceiver) Name() string {
	return "vault-transit"
}
