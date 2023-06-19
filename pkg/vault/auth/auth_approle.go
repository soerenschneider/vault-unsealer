package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
	"github.com/soerenschneider/vault-unsealer/internal/config/vault"
	"io"
	"net/http"
)

type AppRoleAuth struct {
	client *http.Client

	vaultEndpoint string
	conf          vault.AuthApproleConfig
}

type LoginResponse struct {
	Auth struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		TokenPolicies []string `json:"token_policies"`
	}
}

func NewAppRoleAuth(client *http.Client, vaultEndpoint string, conf vault.AuthApproleConfig) (*AppRoleAuth, error) {
	if client == nil {
		log.Warn().Msg("Empty http client passed, building new client")
		client = retryablehttp.NewClient().HTTPClient
	}

	return &AppRoleAuth{
		client:        client,
		conf:          conf,
		vaultEndpoint: vaultEndpoint,
	}, nil
}

func (t *AppRoleAuth) Cleanup() error {
	return errors.New("not implemented")
}

func (t *AppRoleAuth) Authenticate() (string, error) {
	url := fmt.Sprintf("%s/v1/auth/%s/login", t.vaultEndpoint, t.conf.ApproleMountOrDefault())

	data, err := t.conf.GetLoginData()
	if err != nil {
		return "", fmt.Errorf("could not get login data: %v", err)
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	resp, err := http.Post(url, "application/json", bytes.NewReader(jsonData))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	loginResp := LoginResponse{}
	err = json.Unmarshal(body, &loginResp)
	if err != nil {
		return "", nil
	}

	return loginResp.Auth.ClientToken, nil
}
