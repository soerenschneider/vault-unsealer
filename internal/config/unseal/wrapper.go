package unseal

import (
	"errors"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

type WrappedConfig struct {
	WrappedPassphrase     string `yaml:"wrapped_passphrase" validate:"omitempty,min=25"`
	WrappedPassphraseFile string `yaml:"wrapped_passphrase_file" validate:"omitempty,filepath"`
	Cache                 bool   `yaml:"cache"`
}

func (c *WrappedConfig) MustGetWrappedPassphrase() string {
	passphrase, err := c.GetWrappedPassphrase()
	if err != nil {
		log.Fatal().Err(err).Msg("could not read passphrase from file")
	}

	return passphrase
}
func (c *WrappedConfig) GetWrappedPassphrase() (string, error) {
	if c.WrappedPassphraseFile == "" {
		return c.WrappedPassphrase, nil
	}

	data, err := os.ReadFile(c.WrappedPassphraseFile)
	if err != nil {
		return "", err
	}

	passphrase := strings.TrimSpace(string(data))
	if len(passphrase) < 25 {
		return "", errors.New("passphrase must be >= 25 characters")
	}

	return passphrase, nil
}
