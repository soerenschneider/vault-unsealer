package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/soerenschneider/vault-unsealer/v2/internal/config/vault"
	vaultclient "github.com/soerenschneider/vault-unsealer/v2/internal/vault"
)

// tokenRenewalRatio defines after which fraction of its TTL a token is considered expired and a new login is performed.
const tokenRenewalRatio = 0.8

const revokeTimeout = 5 * time.Second

type AppRoleAuth struct {
	vaultEndpoint string
	conf          vault.AuthApproleConfig

	mutex     sync.Mutex
	token     string
	expiresAt time.Time        // zero if the token does not expire
	now       func() time.Time // defaults to time.Now
}

type LoginResponse struct {
	Auth struct {
		ClientToken   string   `json:"client_token"`
		Accessor      string   `json:"accessor"`
		Policies      []string `json:"policies"`
		TokenPolicies []string `json:"token_policies"`
		LeaseDuration int      `json:"lease_duration"`
	}
}

func NewAppRoleAuth(vaultEndpoint string, conf vault.AuthApproleConfig) (*AppRoleAuth, error) {
	return &AppRoleAuth{
		conf:          conf,
		vaultEndpoint: vaultEndpoint,
	}, nil
}

func (t *AppRoleAuth) clock() time.Time {
	if t.now == nil {
		return time.Now()
	}
	return t.now()
}

// Cleanup revokes the current token, if any, and forgets it so the next call to Authenticate performs a new login.
func (t *AppRoleAuth) Cleanup(client *http.Client) error {
	t.mutex.Lock()
	token := t.token
	t.token = ""
	t.expiresAt = time.Time{}
	t.mutex.Unlock()

	if len(token) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), revokeTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/v1/auth/token/revoke-self", t.vaultEndpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Vault-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("could not revoke token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("could not revoke token, received code %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	return nil
}

// Authenticate returns the cached token if it's still valid, otherwise performs a new login.
func (t *AppRoleAuth) Authenticate(client *http.Client) (string, error) {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	if len(t.token) > 0 && (t.expiresAt.IsZero() || t.clock().Before(t.expiresAt)) {
		return t.token, nil
	}

	loginResp, err := t.login(client)
	if err != nil {
		return "", err
	}

	t.token = loginResp.Auth.ClientToken
	t.expiresAt = time.Time{}
	if loginResp.Auth.LeaseDuration > 0 {
		validFor := time.Duration(float64(loginResp.Auth.LeaseDuration)*tokenRenewalRatio) * time.Second
		t.expiresAt = t.clock().Add(validFor)
	}

	return t.token, nil
}

func (t *AppRoleAuth) login(client *http.Client) (*LoginResponse, error) {
	url := fmt.Sprintf("%s/v1/auth/%s/login", t.vaultEndpoint, t.conf.ApproleMountOrDefault())

	data, err := t.conf.GetLoginData()
	if err != nil {
		return nil, fmt.Errorf("could not get login data: %v", err)
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	resp, err := client.Post(url, "application/json", bytes.NewReader(jsonData)) // #nosec G107
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("%w: approle login received code %d: %s", vaultclient.ErrAuth, resp.StatusCode, strings.TrimSpace(string(body)))
	}

	loginResp := LoginResponse{}
	err = json.Unmarshal(body, &loginResp)
	if err != nil {
		return nil, fmt.Errorf("could not parse approle login response: %w", err)
	}

	if len(loginResp.Auth.ClientToken) == 0 {
		return nil, errors.New("invalid response")
	}

	return &loginResp, nil
}
