package auth

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/soerenschneider/vault-unsealer/internal/config/vault"
)

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

func TestApproleAuth_Fail(t *testing.T) {
	body := `{
  "warnings": null,
  "wrap_info": null,
  "data": null,
  "lease_duration": 0,
  "renewable": false,
  "lease_id": ""
}`

	mockTransport := &MockTransport{
		body:       body,
		statusCode: http.StatusUnauthorized,
	}
	client := &http.Client{Transport: mockTransport}
	approle := AppRoleAuth{conf: vault.AuthApproleConfig{
		RoleId:           "xxx",
		SecretId:         "yyy",
		SecretIdFile:     "zzz",
		ApproleMountPath: "aaa",
	},
	}

	_, err := approle.Authenticate(client)
	if err == nil {
		t.Fatal(err)
	}
}

func TestApproleAuth_Success(t *testing.T) {
	body := `{
  "auth": {
    "renewable": true,
    "lease_duration": 1200,
    "metadata": null,
    "token_policies": ["default"],
    "accessor": "fd6c9a00-d2dc-3b11-0be5-af7ae0e1d374",
    "client_token": "5b1a0318-679c-9c45-e5c6-d1b9a9035d49"
  },
  "warnings": null,
  "wrap_info": null,
  "data": null,
  "lease_duration": 0,
  "renewable": false,
  "lease_id": ""
}`

	mockTransport := &MockTransport{
		body:       body,
		statusCode: http.StatusOK,
	}
	client := &http.Client{Transport: mockTransport}
	approle := AppRoleAuth{conf: vault.AuthApproleConfig{
		RoleId:           "xxx",
		SecretId:         "yyy",
		SecretIdFile:     "zzz",
		ApproleMountPath: "aaa",
	},
	}

	token, err := approle.Authenticate(client)
	if err != nil {
		t.Fatal(err)
	}
	expected := "5b1a0318-679c-9c45-e5c6-d1b9a9035d49"
	if token != expected {
		t.Fatalf("expected %s", expected)
	}
}
