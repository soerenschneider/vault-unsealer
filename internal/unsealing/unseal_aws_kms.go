package unsealing

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
)

type AwsKmsKeyRetriever struct {
	ciphertextBlob    []byte
	encryptionContext map[string]string
}

func NewAwsKmsKeyRetriever(cipherText string, encryptionContext map[string]string) (*AwsKmsKeyRetriever, error) {
	if cipherText == "" {
		return nil, errors.New("empty ciphertext provided")
	}

	ciphertextBlob, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %v", err)
	}

	return &AwsKmsKeyRetriever{
		ciphertextBlob:    ciphertextBlob,
		encryptionContext: encryptionContext,
	}, nil
}

func (r *AwsKmsKeyRetriever) RetrieveUnsealKey(ctx context.Context) (string, error) {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to load AWS config: %w", err)
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
