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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	parsed := SealedStatus{}
	err = json.Unmarshal(body, &parsed)

	return &parsed, err
}

func getUnsealPayload(unsealKey string) ([]byte, error) {
	data := map[string]string{
		"key": unsealKey,
	}
	return json.Marshal(data)
}

func (c *SimpleVaultClient) Unseal(ctx context.Context, instance string, unsealKey string) error {
	encodedData, err := getUnsealPayload(unsealKey)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/v1/sys/unseal", instance)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(encodedData))
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		ret, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("received code %d: %s", resp.StatusCode, string(ret))
	}

	return nil
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
		return "", nil
	}

	vaultData, ok := parsedData.Data["data"].(map[string]interface{})
	if !ok {
		return "", errors.New("expected field not found")
	}

	unsealKey, ok := vaultData[reqData.SecretKey]
	if !ok {
		return "", fmt.Errorf("secret key '%s' not found in secret data read from vault", reqData.SecretKey)
	}

	return fmt.Sprintf("%s", unsealKey), nil
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
		return "", nil
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

	decoded, err := base64.StdEncoding.DecodeString(fmt.Sprintf("%s", val))
	if err != nil {
		return "", fmt.Errorf("could not base64 decode received plaintext")
	}

	return strings.TrimSuffix(string(decoded), "\n"), nil
}

func (c *SimpleVaultClient) doPostCall(ctx context.Context, auth AuthMethod, url string, data map[string]string) ([]byte, error) {
	token, err := auth.Authenticate(c.client)
	if err != nil {
		return nil, err
	}
	log.Info().Msg("Received vault token")

	encodedData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(encodedData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return body, nil
}

func (c *SimpleVaultClient) doGetCall(ctx context.Context, auth AuthMethod, url string) ([]byte, error) {
	token, err := auth.Authenticate(c.client)
	if err != nil {
		return nil, err
	}
	log.Info().Msg("Received vault token")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return body, nil
}
