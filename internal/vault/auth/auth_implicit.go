package auth

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/rs/zerolog/log"
)

const (
	tokenEnvVar      = "VAULT_TOKEN"
	defaultTokenFile = ".vault-token"
)

type ImplicitAuth struct {
	tokenFile string
}

func NewTokenImplicitAuth(tokenFile string) *ImplicitAuth {
	if len(tokenFile) == 0 {
		tokenFile = defaultTokenFile
	}

	return &ImplicitAuth{tokenFile: tokenFile}
}

func (t *ImplicitAuth) Authenticate(_ *http.Client) (string, error) {
	token := os.Getenv(tokenEnvVar)
	if len(token) > 0 {
		log.Info().Msgf("Using vault token from env var %s", tokenEnvVar)
		return token, nil
	}

	tokenFile := expandPath(t.tokenFile)
	read, err := os.ReadFile(tokenFile)
	if err != nil {
		return "", fmt.Errorf("error reading file '%s': %v", tokenFile, err)
	}

	log.Info().Msgf("Using vault token from file '%s'", tokenFile)
	return string(read), nil
}

func expandPath(file string) string {
	if len(file) > 0 && file[0] == '~' {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return file
		}

		if len(file) > 1 {
			return filepath.Join(homeDir, file[1:])
		}
		return homeDir
	}

	return file
}

func (t *ImplicitAuth) Cleanup() error {
	return nil
}
