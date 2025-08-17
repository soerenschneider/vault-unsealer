package unsealing

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/soerenschneider/vault-unsealer/internal/config/unseal"
)

type AwsKmsKeyRetriever struct {
	ciphertextBlob    []byte
	encryptionContext map[string]string
	region            string
}

func NewAwsKmsKeyRetriever(conf *unseal.AwsKmsConfig) (*AwsKmsKeyRetriever, error) {
	if conf == nil {
		return nil, errors.New("empty config provided")
	}

	ciphertext, err := conf.GetCiphertext()
	if err != nil {
		return nil, err
	}

	if ciphertext == "" {
		return nil, errors.New("empty ciphertext provided")
	}

	ciphertextBlob, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	return &AwsKmsKeyRetriever{
		ciphertextBlob:    ciphertextBlob,
		encryptionContext: conf.EncryptionContext,
		region:            conf.Region,
	}, nil
}

func (r *AwsKmsKeyRetriever) RetrieveUnsealKey(ctx context.Context) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
	}

	if r.region != "" {
		cfg.Region = r.region
	}

	client := kms.NewFromConfig(cfg)

	resp, err := client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob:    r.ciphertextBlob,
		EncryptionContext: r.encryptionContext,
	})
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(resp.Plaintext), nil
}

func (r *AwsKmsKeyRetriever) Name() string {
	return "aws-kms"
}
