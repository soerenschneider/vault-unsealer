package vault

type AuthTokenConfig struct {
	Token string `yaml:"token" validate:"required"`
}
