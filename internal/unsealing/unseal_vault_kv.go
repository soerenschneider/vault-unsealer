package unsealing

import (
	"context"
	"errors"

	"github.com/soerenschneider/vault-unsealer/internal/config/unseal"
	"github.com/soerenschneider/vault-unsealer/pkg/vault"
)

type VaultKv2 interface {
	ReadKv2(ctx context.Context, auth vault.AuthMethod, instance string, reqData vault.ReadVaultKv2Request) (string, error)
}

type VaultKvRetriever struct {
	vaultEndpoint string `validate:"required"`
	authMethod    vault.AuthMethod
	vaultClient   VaultKv2 `validate:"required"`

	config unseal.VaultKv2Config
}

func NewVaultKvRetriever(client VaultKv2, auth vault.AuthMethod, config unseal.VaultKv2Config) (*VaultKvRetriever, error) {
	if client == nil {
		return nil, errors.New("empty VaultKv2 client provided")
	}

	if auth == nil {
		return nil, errors.New("emtpy AuthMethod provided")
	}

	return &VaultKvRetriever{
		vaultEndpoint: config.VaultEndpoint,
		authMethod:    auth,
		vaultClient:   client,
		config:        config,
	}, nil
}

func (r *VaultKvRetriever) RetrieveUnsealKey(ctx context.Context) (string, error) {
	reqData := vault.ReadVaultKv2Request{
		MountPath:  r.config.MountPathOrDefault(),
		SecretPath: r.config.VaultKv2SecretPath,
		SecretKey:  r.config.SecretKeyOrDefault(),
	}

	return r.vaultClient.ReadKv2(ctx, r.authMethod, r.vaultEndpoint, reqData)
}

func (r *VaultKvRetriever) Name() string {
	return "vault-kv"
}
