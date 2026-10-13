package vault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
)

type NoAuth struct {
	token string
	err   error
}

func (n *NoAuth) Cleanup(_ *http.Client) error {
	return nil
}

func (n *NoAuth) Authenticate(client *http.Client) (string, error) {
	return n.token, n.err
}

// MockTransport implements the RoundTripper interface
type MockTransport struct {
	body       string
	statusCode int
}

// RoundTrip is a mock implementation of the RoundTripper interface
func (t *MockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Create a mock response
	mockResponse := &http.Response{
		StatusCode: t.statusCode,
		Body:       io.NopCloser(bytes.NewBufferString(t.body)),
	}

	return mockResponse, nil
}

func TestSimpleVaultClient_GetSealedStatus(t *testing.T) {
	body := `{
  "type": "shamir",
  "initialized": true,
  "sealed": true,
  "t": 3,
  "n": 5,
  "progress": 2,
  "nonce": "",
  "version": "1.11.0",
  "build_date": "2022-05-03T08:34:11Z",
  "migration": false,
  "recovery_seal": false,
  "storage_type": "file"
}`

	mockTransport := &MockTransport{
		body:       body,
		statusCode: http.StatusOK,
	}
	client := &http.Client{Transport: mockTransport}
	vaultClient, err := NewSimpleVaultClient(client)
	if err != nil {
		t.Fatal(err)
	}

	status, err := vaultClient.GetSealedStatus(context.Background(), "http://vault")
	if err != nil {
		t.Fatal(err)
	}

	expected := true
	if status.Sealed != expected {
		t.Fatalf("expected sealed = %t", expected)
	}
}

func TestSimpleVaultClient_ReadKv2(t *testing.T) {
	body := `{
  "data": {
    "data": {
      "foo": "bar"
    },
    "metadata": {
      "created_time": "2018-03-22T02:24:06.945319214Z",
      "custom_metadata": {
        "owner": "jdoe",
        "mission_critical": "false"
      },
      "deletion_time": "",
      "destroyed": false,
      "version": 2
    }
  }
}`

	mockTransport := &MockTransport{
		body:       body,
		statusCode: http.StatusOK,
	}
	client := &http.Client{Transport: mockTransport}
	vaultClient, err := NewSimpleVaultClient(client)
	if err != nil {
		t.Fatal(err)
	}

	auth := &NoAuth{}
	req := ReadVaultKv2Request{
		SecretKey: "foo",
	}
	secret, err := vaultClient.ReadKv2(context.Background(), auth, "", req)
	if err != nil {
		t.Fatal(err)
	}
	expected := "bar"
	if secret != expected {
		t.Fatalf("expected %s, got %s", expected, secret)
	}
}

func TestSimpleVaultClient_ReadKv2_AuthProblem(t *testing.T) {
	body := `{
  "data": {
    "data": {
      "foo": "bar"
    },
    "metadata": {
      "created_time": "2018-03-22T02:24:06.945319214Z",
      "custom_metadata": {
        "owner": "jdoe",
        "mission_critical": "false"
      },
      "deletion_time": "",
      "destroyed": false,
      "version": 2
    }
  }
}`

	mockTransport := &MockTransport{
		body:       body,
		statusCode: http.StatusUnauthorized,
	}
	client := &http.Client{Transport: mockTransport}
	vaultClient, err := NewSimpleVaultClient(client)
	if err != nil {
		t.Fatal(err)
	}

	auth := &NoAuth{
		err: errors.New("computer says no"),
	}
	req := ReadVaultKv2Request{
		SecretKey: "foo",
	}
	_, err = vaultClient.ReadKv2(context.Background(), auth, "", req)
	if err == nil {
		t.Fatal(err)
	}
}

func TestSimpleVaultClient_ReadKv2_MalformedSecret(t *testing.T) {
	body := `{
  "data": {
    "data": {
      "foo": "bar"
    },
    "metadata": {
      "created_time": "2018-03-22T02:24:06.945319214Z",
      "custom_metadata": {
        "owner": "jdoe",
        "mission_critical": "false"
      },
      "deletion_time": "",
      "destroyed": false,
      "version": 2
    }
  }
}`

	mockTransport := &MockTransport{
		body:       body,
		statusCode: http.StatusOK,
	}
	client := &http.Client{Transport: mockTransport}
	vaultClient, err := NewSimpleVaultClient(client)
	if err != nil {
		t.Fatal(err)
	}

	auth := &NoAuth{}
	req := ReadVaultKv2Request{
		SecretKey: "yada",
	}
	_, err = vaultClient.ReadKv2(context.Background(), auth, "", req)
	if err == nil {
		t.Fatal(err)
	}
}

func TestSimpleVaultClient_Decrypt(t *testing.T) {
	body := `{
  "data": {
    "plaintext": "dGhlIHF1aWNrIGJyb3duIGZveAo="
  }
}`

	mockTransport := &MockTransport{
		body:       body,
		statusCode: http.StatusOK,
	}
	client := &http.Client{Transport: mockTransport}
	vaultClient, err := NewSimpleVaultClient(client)
	if err != nil {
		t.Fatal(err)
	}

	auth := &NoAuth{}
	req := TransitDecryptRequest{
		MountPath:         "",
		EncryptionKeyName: "",
		Ciphertext:        "",
	}
	secret, err := vaultClient.Decrypt(context.Background(), auth, "inst", req)
	if err != nil {
		t.Fatal(err)
	}

	expected := "the quick brown fox"
	if expected != secret {
		t.Fatalf("expected %s, got %s", expected, secret)
	}
}

func newMockClient(t *testing.T, statusCode int, body string) *SimpleVaultClient {
	t.Helper()
	client := &http.Client{Transport: &MockTransport{body: body, statusCode: statusCode}}
	vaultClient, err := NewSimpleVaultClient(client)
	if err != nil {
		t.Fatal(err)
	}
	return vaultClient
}

func TestSimpleVaultClient_GetSealedStatus_Errors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "server error", statusCode: http.StatusInternalServerError, body: `{"errors":["internal error"]}`},
		{name: "invalid json", statusCode: http.StatusOK, body: `<html>proxy error</html>`},
		{name: "missing sealed field", statusCode: http.StatusOK, body: `{}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newMockClient(t, tt.statusCode, tt.body).GetSealedStatus(context.Background(), "http://vault")
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestSimpleVaultClient_GetSealedStatus_Unsealed(t *testing.T) {
	status, err := newMockClient(t, http.StatusOK, `{"sealed": false, "cluster_id": "abc"}`).GetSealedStatus(context.Background(), "http://vault")
	if err != nil {
		t.Fatal(err)
	}
	if status.Sealed || status.ClusterId != "abc" {
		t.Fatalf("unexpected status: %s", status)
	}
}

func TestSimpleVaultClient_Unseal_Error(t *testing.T) {
	_, err := newMockClient(t, http.StatusBadRequest, `{"errors":["invalid key"]}`).Unseal(context.Background(), "http://vault", "key")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSimpleVaultClient_Decrypt_Errors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantAuth   bool
	}{
		{name: "permission denied", statusCode: http.StatusForbidden, body: `{"errors":["permission denied"]}`, wantAuth: true},
		{name: "server error", statusCode: http.StatusServiceUnavailable, body: `{"errors":["Vault is sealed"]}`},
		{name: "invalid json", statusCode: http.StatusOK, body: `not json`},
		{name: "empty plaintext", statusCode: http.StatusOK, body: `{"data":{"plaintext":""}}`},
		{name: "non-string plaintext", statusCode: http.StatusOK, body: `{"data":{"plaintext":42}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newMockClient(t, tt.statusCode, tt.body).Decrypt(context.Background(), &NoAuth{}, "http://vault", TransitDecryptRequest{})
			if err == nil {
				t.Fatal("expected error")
			}
			if tt.wantAuth != errors.Is(err, ErrAuth) {
				t.Fatalf("expected errors.Is(err, ErrAuth) = %t, got err %v", tt.wantAuth, err)
			}
		})
	}
}

func TestSimpleVaultClient_ReadKv2_Errors(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "not found", statusCode: http.StatusNotFound, body: `{"errors":[]}`},
		{name: "invalid json", statusCode: http.StatusOK, body: `not json`},
		{name: "empty value", statusCode: http.StatusOK, body: `{"data":{"data":{"foo":""}}}`},
		{name: "non-string value", statusCode: http.StatusOK, body: `{"data":{"data":{"foo":{"nested":true}}}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newMockClient(t, tt.statusCode, tt.body).ReadKv2(context.Background(), &NoAuth{}, "http://vault", ReadVaultKv2Request{SecretKey: "foo"})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

type rotatingAuth struct {
	tokens   []string
	cleanups int
	err      error
}

func (a *rotatingAuth) Authenticate(_ *http.Client) (string, error) {
	if a.err != nil {
		return "", a.err
	}
	return a.tokens[a.cleanups], nil
}

func (a *rotatingAuth) Cleanup(_ *http.Client) error {
	a.cleanups++
	return nil
}

// tokenTransport only accepts requests carrying the given token.
type tokenTransport struct {
	validToken string
	requests   int
}

func (t *tokenTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.requests++
	if req.Header.Get("X-Vault-Token") != t.validToken {
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(bytes.NewBufferString(`{"errors":["permission denied"]}`))}, nil
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"data":{"data":{"foo":"bar"}}}`))}, nil
}

func TestSimpleVaultClient_RetriesWithNewTokenWhenRejected(t *testing.T) {
	transport := &tokenTransport{validToken: "fresh"}
	vaultClient, _ := NewSimpleVaultClient(&http.Client{Transport: transport})
	auth := &rotatingAuth{tokens: []string{"stale", "fresh"}}

	secret, err := vaultClient.ReadKv2(context.Background(), auth, "http://vault", ReadVaultKv2Request{SecretKey: "foo"})
	if err != nil {
		t.Fatal(err)
	}
	if secret != "bar" || auth.cleanups != 1 || transport.requests != 2 {
		t.Fatalf("expected one cleanup and retry, got secret=%q cleanups=%d requests=%d", secret, auth.cleanups, transport.requests)
	}
}

func TestSimpleVaultClient_RetriesOnlyOnce(t *testing.T) {
	transport := &tokenTransport{validToken: "never"}
	vaultClient, _ := NewSimpleVaultClient(&http.Client{Transport: transport})
	auth := &rotatingAuth{tokens: []string{"a", "b", "c"}}

	_, err := vaultClient.ReadKv2(context.Background(), auth, "http://vault", ReadVaultKv2Request{SecretKey: "foo"})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("expected ErrAuth, got %v", err)
	}
	if transport.requests != 2 {
		t.Fatalf("expected 2 requests, got %d", transport.requests)
	}
}

func TestSimpleVaultClient_NoRetryWhenLoginFails(t *testing.T) {
	transport := &tokenTransport{validToken: "x"}
	vaultClient, _ := NewSimpleVaultClient(&http.Client{Transport: transport})
	auth := &rotatingAuth{err: fmt.Errorf("%w: invalid secret id", ErrAuth)}

	_, err := vaultClient.ReadKv2(context.Background(), auth, "http://vault", ReadVaultKv2Request{SecretKey: "foo"})
	if err == nil || auth.cleanups != 0 || transport.requests != 0 {
		t.Fatalf("expected login error without retry, got err=%v cleanups=%d requests=%d", err, auth.cleanups, transport.requests)
	}
}

func TestSimpleVaultClient_Unseal_KeyRejected(t *testing.T) {
	tests := []struct {
		name         string
		statusCode   int
		wantRejected bool
	}{
		{name: "invalid key", statusCode: http.StatusBadRequest, wantRejected: true},
		{name: "server error", statusCode: http.StatusInternalServerError, wantRejected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newMockClient(t, tt.statusCode, `{"errors":["error"]}`).Unseal(context.Background(), "http://vault", "key")
			if err == nil {
				t.Fatal("expected error")
			}
			if errors.Is(err, ErrUnsealKeyRejected) != tt.wantRejected {
				t.Fatalf("expected errors.Is(err, ErrUnsealKeyRejected) = %t, got %v", tt.wantRejected, err)
			}
		})
	}
}

// recordingTransport records the body of the last request.
type recordingTransport struct {
	body string
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	t.body = string(body)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewBufferString(`{"sealed":true}`))}, nil
}

func TestSimpleVaultClient_ResetUnseal(t *testing.T) {
	transport := &recordingTransport{}
	vaultClient, _ := NewSimpleVaultClient(&http.Client{Transport: transport})
	if err := vaultClient.ResetUnseal(context.Background(), "http://vault"); err != nil {
		t.Fatal(err)
	}
	if transport.body != `{"reset":true}` {
		t.Fatalf("unexpected request body %q", transport.body)
	}
}

func TestSimpleVaultClient_Unseal_ReturnsProgress(t *testing.T) {
	status, err := newMockClient(t, http.StatusOK, `{"sealed":true,"t":3,"n":5,"progress":2}`).Unseal(context.Background(), "http://vault", "key")
	if err != nil {
		t.Fatal(err)
	}
	if !status.Sealed || status.Threshold != 3 || status.Progress != 2 {
		t.Fatalf("unexpected status %+v", status)
	}
}
