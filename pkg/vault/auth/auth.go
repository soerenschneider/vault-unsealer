package auth

import (
	"fmt"
	"net/http"

	"github.com/rs/zerolog/log"
	"github.com/soerenschneider/vault-unsealer/internal/config"
	vault_auth "github.com/soerenschneider/vault-unsealer/internal/config/vault"
	"github.com/soerenschneider/vault-unsealer/pkg/vault"
)

func BuildVaultAuth(authType string, authData map[string]any, vaultEndpoint string, httpClient *http.Client) (vault.AuthMethod, error) {
	switch authType {
	case "implicit":
		log.Info().Msg("Building 'implicit' vault auth implementation")
		return NewTokenImplicitAuth(), nil
	case "token":
		log.Info().Msg("Building 'token' vault auth implementation")
		conf, err := config.UnmarshalGeneric[vault_auth.AuthTokenConfig](authData)
		if err != nil {
			return nil, err
		}
		return NewTokenAuth(conf.Token)
	case "approle":
		log.Info().Msg("Building 'approle' vault auth implementation")
		conf, err := config.UnmarshalGeneric[vault_auth.AuthApproleConfig](authData)
		if err != nil {
			return nil, err
		}
		return NewAppRoleAuth(vaultEndpoint, *conf)
	default:
		return nil, fmt.Errorf("unknown vault auth implementation: %s", authType)
	}
}
