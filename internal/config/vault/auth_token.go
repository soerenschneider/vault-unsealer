package vault

type AuthTokenConfig struct {
	Token string `json:"token" validate:"required"`
}
