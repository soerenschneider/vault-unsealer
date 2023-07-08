package auth

import "net/http"

type TokenAuth struct {
	token string
}

func NewTokenAuth(token string) (*TokenAuth, error) {
	return &TokenAuth{token}, nil
}

func (t *TokenAuth) Authenticate(_ *http.Client) (string, error) {
	return t.token, nil
}

func (t *TokenAuth) Cleanup() error {
	return nil
}
