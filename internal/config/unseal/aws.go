package unseal

import "os"

type AwsKmsConfig struct {
	AwsTransitCiphertextFile string            `yaml:"aws_transit_ciphertext_file" validate:"required_without=AwsTransitCiphertext,omitempty,file"`
	AwsTransitCiphertext     string            `yaml:"aws_transit_ciphertext" validate:"required_without=AwsTransitCiphertextFile,omitempty"`
	Region                   string            `yaml:"aws_region"`
	EncryptionContext        map[string]string `yaml:"encryption_context"`
	WrappedConfig            `yaml:",inline"`
}

func (c *AwsKmsConfig) GetCiphertext() (string, error) {
	if len(c.AwsTransitCiphertextFile) == 0 {
		return c.AwsTransitCiphertext, nil
	}

	ciphertext, err := os.ReadFile(c.AwsTransitCiphertextFile)
	if err != nil {
		return "", err
	}

	return string(ciphertext), nil
}
