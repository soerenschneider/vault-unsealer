package vault

import (
	"errors"
	"fmt"
	"os"
)

const (
	defaultApproleMountPath = "approle"
	KeyRoleId               = "role_id"
	KeySecretId             = "secret_id"
)

type AuthApproleConfig struct {
	RoleId           string `yaml:"role_id" validate:"required"`
	SecretId         string `yaml:"secret_id"`
	SecretIdFile     string `yaml:"secret_id_file"`
	ApproleMountPath string `yaml:"approle_mount"`
}

func (c *AuthApproleConfig) ApproleMountOrDefault() string {
	if len(c.ApproleMountPath) == 0 {
		return defaultApproleMountPath
	}

	return c.ApproleMountPath
}

func (c *AuthApproleConfig) GetLoginData() (map[string]string, error) {
	loginData := map[string]string{
		KeyRoleId: c.RoleId,
	}

	if len(c.SecretId) > 0 {
		loginData[KeySecretId] = c.SecretId
		return loginData, nil
	}

	if len(c.SecretIdFile) == 0 {
		return nil, errors.New("neither secret_id nor secret_id_file provided")
	}

	data, err := os.ReadFile(c.SecretIdFile)
	if err != nil {
		return nil, fmt.Errorf("could not read secret_id from file '%s': %v", c.SecretIdFile, err)
	}
	loginData[KeySecretId] = string(data)
	return loginData, nil
}
