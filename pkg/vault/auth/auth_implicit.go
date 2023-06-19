package auth

import (
	"errors"
	"fmt"
	"github.com/rs/zerolog/log"
	"os"
	"path"
)

const (
	tokenEnvVar = "VAULT_TOKEN"
	tokenFile   = ".vault-token"
)

type ImplicitAuth struct {
}

func NewTokenImplicitAuth() *ImplicitAuth {
	return &ImplicitAuth{}
}

func (t *ImplicitAuth) Authenticate() (string, error) {
	token := os.Getenv(tokenEnvVar)
	if len(token) > 0 {
		log.Info().Msgf("Using vault token from env var %s", tokenEnvVar)
		return token, nil
	}

	dirname, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("can't get user home dir: %v", err)
	}

	tokenPath := path.Join(dirname, tokenFile)
	if _, err := os.Stat(tokenPath); errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("file '%s' to read vault token from does not exist", tokenPath)
	}

	read, err := os.ReadFile(tokenPath)
	if err != nil {
		return "", fmt.Errorf("error reading file '%s': %v", tokenPath, err)
	}

	log.Info().Msgf("Using vault token from file '%s'", tokenPath)
	return string(read), nil
}

func (t *ImplicitAuth) Cleanup() error {
	return nil
}
