package unseal

type WrappedConfig struct {
	WrappedPassphrase string `yaml:"wrapped_passphrase" validate:"omitempty,min=25"`
	Cache             bool   `yaml:"cache"`
}
