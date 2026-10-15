package unsealing

import (
	"encoding/base64"
	"testing"

	"github.com/soerenschneider/vault-unsealer/v2/internal/config/unseal"
)

func TestAwsKmsKeyRetriever_DecryptInput(t *testing.T) {
	ciphertext := base64.StdEncoding.EncodeToString([]byte("blob"))

	tests := []struct {
		name      string
		keyId     string
		wantKeyId bool
	}{
		{name: "without key id", keyId: ""},
		{name: "with key id", keyId: "arn:aws:kms:eu-central-1:111122223333:key/1234abcd", wantKeyId: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			retriever, err := NewAwsKmsKeyRetriever(&unseal.AwsKmsConfig{
				AwsTransitCiphertext: ciphertext,
				EncryptionContext:    map[string]string{"purpose": "vault-unseal"},
				KeyId:                tt.keyId,
			})
			if err != nil {
				t.Fatal(err)
			}

			input := retriever.decryptInput()
			if string(input.CiphertextBlob) != "blob" || input.EncryptionContext["purpose"] != "vault-unseal" {
				t.Fatalf("unexpected input %+v", input)
			}
			if tt.wantKeyId {
				if input.KeyId == nil || *input.KeyId != tt.keyId {
					t.Fatalf("expected key id %q, got %v", tt.keyId, input.KeyId)
				}
			} else if input.KeyId != nil {
				t.Fatalf("expected no key id, got %q", *input.KeyId)
			}
		})
	}
}
