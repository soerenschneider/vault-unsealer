package unsealing

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"filippo.io/age"
)

type AgeWrapper struct {
	passphrase string
	retriever  UnsealKeyRetriever
}

func NewAgeWrapper(passphrase string, retriever UnsealKeyRetriever) (*AgeWrapper, error) {
	if len(passphrase) < 25 {
		return nil, errors.New("passphrase too short, need at least 25 chars")
	}

	if retriever == nil {
		return nil, errors.New("empty retriever provided")
	}

	return &AgeWrapper{
		passphrase: passphrase,
		retriever:  retriever,
	}, nil
}

func (w *AgeWrapper) RetrieveUnsealKey(ctx context.Context) (string, error) {
	ciphertext, err := w.retriever.RetrieveUnsealKey(ctx)
	if err != nil {
		return "", fmt.Errorf("could not retrieve unseal ciphertext from wrapped retriever: %w", err)
	}

	return DecryptWithPassphrase(ciphertext, w.passphrase)
}

// DecryptWithPassphrase decrypts a base64-encoded ciphertext using a passphrase
// Returns plaintext string or error
func DecryptWithPassphrase(ciphertext, passphrase string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64: %v", err)
	}

	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to create identity: %v", err)
	}

	r, err := age.Decrypt(bytes.NewReader(data), identity)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %v", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		return "", fmt.Errorf("failed to read decrypted data: %v", err)
	}

	return buf.String(), nil
}

// EncryptWithPassphrase encrypts a plaintext string using a passphrase
// Returns base64-encoded ciphertext or error
func EncryptWithPassphrase(plaintext, passphrase string) (string, error) {
	if len(passphrase) < 25 {
		return "", errors.New("passphrase too short, need at least 25 chars")
	}

	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return "", fmt.Errorf("failed to create recipient: %v", err)
	}

	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return "", fmt.Errorf("failed to create encrypter: %v", err)
	}

	if _, err := io.WriteString(w, plaintext); err != nil {
		return "", fmt.Errorf("failed to write plaintext: %v", err)
	}

	if err := w.Close(); err != nil {
		return "", fmt.Errorf("failed to close encrypter: %v", err)
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func (r *AgeWrapper) Name() string {
	return fmt.Sprintf("age-%s", r.retriever.Name())
}
