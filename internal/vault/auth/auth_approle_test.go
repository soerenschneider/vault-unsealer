package auth

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/soerenschneider/vault-unsealer/v2/internal/config/vault"
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

func TestApproleAuth_InvalidResponse(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "invalid json", statusCode: http.StatusOK, body: `<html>proxy error</html>`},
		{name: "server error with token", statusCode: http.StatusInternalServerError, body: `{"auth":{"client_token":"abc"}}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Transport: &MockTransport{body: tt.body, statusCode: tt.statusCode}}
			approle := AppRoleAuth{conf: vault.AuthApproleConfig{RoleId: "xxx", SecretId: "yyy"}}

			token, err := approle.Authenticate(client)
			if err == nil {
				t.Fatalf("expected error, got token %q", token)
			}
		})
	}
}

type fakeVault struct {
	server        *httptest.Server
	logins        atomic.Int32
	revokedTokens chan string
	leaseDuration int
}

func newFakeVault(t *testing.T, leaseDuration int) *fakeVault {
	t.Helper()
	fv := &fakeVault{revokedTokens: make(chan string, 10), leaseDuration: leaseDuration}
	fv.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/approle/login":
			n := fv.logins.Add(1)
			_, _ = fmt.Fprintf(w, `{"auth":{"client_token":"token-%d","lease_duration":%d}}`, n, fv.leaseDuration)
		case "/v1/auth/token/revoke-self":
			fv.revokedTokens <- r.Header.Get("X-Vault-Token")
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(fv.server.Close)
	return fv
}

func TestApproleAuth_ReusesTokenUntilExpiry(t *testing.T) {
	fv := newFakeVault(t, 100)
	now := time.Now()
	approle, _ := NewAppRoleAuth(fv.server.URL, vault.AuthApproleConfig{RoleId: "role", SecretId: "secret"})
	approle.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		token, err := approle.Authenticate(fv.server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if token != "token-1" {
			t.Fatalf("expected cached token-1, got %s", token)
		}
	}

	// 80% of the lease duration has passed
	now = now.Add(80 * time.Second)
	token, err := approle.Authenticate(fv.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if token != "token-2" {
		t.Fatalf("expected new token-2 after expiry, got %s", token)
	}
	if got := fv.logins.Load(); got != 2 {
		t.Fatalf("expected 2 logins, got %d", got)
	}
}

func TestApproleAuth_TokenWithoutTtl(t *testing.T) {
	fv := newFakeVault(t, 0)
	now := time.Now()
	approle, _ := NewAppRoleAuth(fv.server.URL, vault.AuthApproleConfig{RoleId: "role", SecretId: "secret"})
	approle.now = func() time.Time { return now }

	_, _ = approle.Authenticate(fv.server.Client())
	now = now.Add(24 * 365 * time.Hour)
	token, _ := approle.Authenticate(fv.server.Client())
	if token != "token-1" || fv.logins.Load() != 1 {
		t.Fatalf("expected token without ttl to be reused, got %s after %d logins", token, fv.logins.Load())
	}
}

func TestApproleAuth_CleanupRevokesToken(t *testing.T) {
	fv := newFakeVault(t, 100)
	approle, _ := NewAppRoleAuth(fv.server.URL, vault.AuthApproleConfig{RoleId: "role", SecretId: "secret"})

	// nothing to revoke yet
	if err := approle.Cleanup(fv.server.Client()); err != nil {
		t.Fatal(err)
	}
	if len(fv.revokedTokens) != 0 {
		t.Fatal("expected no revocation without a token")
	}

	if _, err := approle.Authenticate(fv.server.Client()); err != nil {
		t.Fatal(err)
	}
	if err := approle.Cleanup(fv.server.Client()); err != nil {
		t.Fatal(err)
	}
	if revoked := <-fv.revokedTokens; revoked != "token-1" {
		t.Fatalf("expected token-1 to be revoked, got %q", revoked)
	}

	// token is forgotten after cleanup
	token, err := approle.Authenticate(fv.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if token != "token-2" {
		t.Fatalf("expected new login after cleanup, got %s", token)
	}
}
