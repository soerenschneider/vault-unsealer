package vault

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/rs/zerolog/log"
)

var ErrAuth = errors.New("authentication failed")

// ErrUnsealKeyRejected is returned if Vault does not accept an unseal key, e.g. because it's malformed or, once the
// threshold of key shares is reached, the combined key is wrong.
var ErrUnsealKeyRejected = errors.New("unseal key rejected")

type SimpleVaultClient struct {
	client *http.Client
}

func NewSimpleVaultClient(client *http.Client) (*SimpleVaultClient, error) {
	if client == nil {
		client = retryablehttp.NewClient().StandardClient()
	}
	return &SimpleVaultClient{
		client: client,
	}, nil
}

func (c *SimpleVaultClient) GetSealedStatus(ctx context.Context, instance string) (*SealedStatus, error) {
	url := fmt.Sprintf("%s/v1/sys/seal-status", instance)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := readResponse(resp)
	if err != nil {
		return nil, err
	}

	return parseSealStatus(body)
}

func parseSealStatus(body []byte) (*SealedStatus, error) {
	// decode into a pointer to tell a missing 'sealed' field apart from 'sealed: false'
	parsed := struct {
		SealedStatus
		Sealed *bool `json:"sealed"`
	}{}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("could not parse seal status: %w", err)
	}
	if parsed.Sealed == nil {
		return nil, errors.New("seal status response does not contain field 'sealed'")
	}

	parsed.SealedStatus.Sealed = *parsed.Sealed
	return &parsed.SealedStatus, nil
}

func (c *SimpleVaultClient) Unseal(ctx context.Context, instance string, unsealKey string) (*SealedStatus, error) {
	resp, err := c.postUnseal(ctx, instance, map[string]any{"key": unsealKey})
	if err != nil {
		return nil, err
	}

	body, err := readResponse(resp)
	if err != nil {
		if resp.StatusCode == http.StatusBadRequest {
			return nil, fmt.Errorf("%w: %w", ErrUnsealKeyRejected, err)
		}
		return nil, err
	}

	return parseSealStatus(body)
}

// ResetUnseal discards all unseal keys that have been submitted so far.
func (c *SimpleVaultClient) ResetUnseal(ctx context.Context, instance string) error {
	resp, err := c.postUnseal(ctx, instance, map[string]any{"reset": true})
	if err != nil {
		return err
	}

	_, err = readResponse(resp)
	return err
}

func (c *SimpleVaultClient) postUnseal(ctx context.Context, instance string, payload map[string]any) (*http.Response, error) {
	encodedData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("%s/v1/sys/unseal", instance)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(encodedData))
	if err != nil {
		return nil, err
	}

	return c.client.Do(req)
}

func (c *SimpleVaultClient) ReadKv2(ctx context.Context, auth AuthMethod, instance string, reqData ReadVaultKv2Request) (string, error) {
	url := fmt.Sprintf("%s/v1/%s/data/%s", instance, reqData.MountPath, reqData.SecretPath)
	body, err := c.doGetCall(ctx, auth, url)
	if err != nil {
		return "", err
	}

	parsedData := struct {
		Data map[string]interface{} `json:"data"`
	}{}
	if err = json.Unmarshal(body, &parsedData); err != nil {
		return "", fmt.Errorf("could not parse kv2 response: %w", err)
	}

	vaultData, ok := parsedData.Data["data"].(map[string]interface{})
	if !ok {
		return "", errors.New("expected field not found")
	}

	unsealKey, ok := vaultData[reqData.SecretKey]
	if !ok {
		return "", fmt.Errorf("secret key '%s' not found in secret data read from vault", reqData.SecretKey)
	}

	unsealKeyStr, ok := unsealKey.(string)
	if !ok || len(unsealKeyStr) == 0 {
		return "", fmt.Errorf("secret key '%s' is not a non-empty string", reqData.SecretKey)
	}

	return unsealKeyStr, nil
}

func (c *SimpleVaultClient) Decrypt(ctx context.Context, auth AuthMethod, instance string, reqData TransitDecryptRequest) (string, error) {
	url := fmt.Sprintf("%s/v1/%s/decrypt/%s", instance, reqData.MountPath, reqData.EncryptionKeyName)
	log.Info().Msgf("Trying to decrypt unseal key using %s", url)
	data := map[string]string{
		"ciphertext": reqData.Ciphertext,
	}
	body, err := c.doPostCall(ctx, auth, url, data)
	if err != nil {
		return "", err
	}

	jsonData := map[string]interface{}{}
	err = json.Unmarshal(body, &jsonData)
	if err != nil {
		return "", fmt.Errorf("could not parse transit response: %w", err)
	}

	val, ok := jsonData["data"]
	if !ok {
		return "", errors.New("expected field `data` not found")
	}
	dataContent, ok := val.(map[string]any)
	if !ok {
		return "", errors.New("could not cast 'data' field")
	}

	val, ok = dataContent["plaintext"]
	if !ok {
		return "", errors.New("no plaintext field found")
	}

	plaintext, ok := val.(string)
	if !ok {
		return "", errors.New("could not cast 'plaintext' field")
	}

	decoded, err := base64.StdEncoding.DecodeString(plaintext)
	if err != nil {
		return "", fmt.Errorf("could not base64 decode received plaintext")
	}

	unsealKey := strings.TrimSuffix(string(decoded), "\n")
	if len(unsealKey) == 0 {
		return "", errors.New("decrypted plaintext is empty")
	}

	return unsealKey, nil
}

func (c *SimpleVaultClient) doPostCall(ctx context.Context, auth AuthMethod, url string, data map[string]string) ([]byte, error) {
	encodedData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return c.doAuthenticatedCall(ctx, auth, http.MethodPost, url, encodedData)
}

func (c *SimpleVaultClient) doGetCall(ctx context.Context, auth AuthMethod, url string) ([]byte, error) {
	return c.doAuthenticatedCall(ctx, auth, http.MethodGet, url, nil)
}

// doAuthenticatedCall performs a request using a token from the given AuthMethod. If Vault rejects the token, e.g.
// because it has been revoked or its number of uses is exhausted, the token is discarded and the request is retried
// once with a fresh token.
func (c *SimpleVaultClient) doAuthenticatedCall(ctx context.Context, auth AuthMethod, method, url string, payload []byte) ([]byte, error) {
	body, err := c.doTokenCall(ctx, auth, method, url, payload)
	if !errors.Is(err, errTokenRejected) {
		return body, err
	}

	log.Warn().Err(err).Msg("Vault rejected token, retrying with a new token")
	if err := auth.Cleanup(c.client); err != nil {
		log.Debug().Err(err).Msg("Could not clean up rejected token")
	}

	return c.doTokenCall(ctx, auth, method, url, payload)
}

var errTokenRejected = errors.New("token rejected")

func (c *SimpleVaultClient) doTokenCall(ctx context.Context, auth AuthMethod, method, url string, payload []byte) ([]byte, error) {
	token, err := auth.Authenticate(c.client)
	if err != nil {
		return nil, err
	}

	var reqBody io.Reader
	if payload != nil {
		reqBody = bytes.NewReader(payload)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := readResponse(resp)
	if errors.Is(err, ErrAuth) {
		return nil, fmt.Errorf("%w: %w", errTokenRejected, err)
	}
	return body, err
}

// readResponse reads and closes the response body and returns an error for non-2xx status codes.
func readResponse(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		err := fmt.Errorf("received code %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			return nil, fmt.Errorf("%w: %w", ErrAuth, err)
		}
		return nil, err
	}

	return body, nil
}
