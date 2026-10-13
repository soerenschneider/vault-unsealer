package vault

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

type NoAuth struct {
	token string
	err   error
}

func (n *NoAuth) Cleanup() error {
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
		statusCode: http.StatusUnauthorized,
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
