package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/rs/zerolog/log"
	"github.com/soerenschneider/vault-unsealer/internal/unsealing"
	"golang.org/x/term"
)

// AskCredentials securely asks for a token and optionally a passphrase
func AskCredentials() (token string, passphrase string, err error) {
	// Prompt for token
	fmt.Print("Enter token: ")
	byteToken, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", "", fmt.Errorf("failed to read token: %w", err)
	}
	fmt.Println() // move to next line
	token = strings.TrimSpace(string(byteToken))

	// Ask if user wants to add passphrase
	var choice string
	for choice != "y" && choice != "n" && choice != "yes" && choice != "no" {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("Do you want to add a passphrase? (y/n): ")
		choice, _ = reader.ReadString('\n')
		choice = strings.TrimSpace(strings.ToLower(choice))

		if choice == "y" || choice == "yes" {
			// Ask for passphrase
			fmt.Print("Enter passphrase: ")
			pass1, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return "", "", fmt.Errorf("failed to read passphrase: %w", err)
			}
			fmt.Println()

			fmt.Print("Confirm passphrase: ")
			pass2, err := term.ReadPassword(int(os.Stdin.Fd()))
			if err != nil {
				return "", "", fmt.Errorf("failed to read confirmation: %w", err)
			}
			fmt.Println()

			if string(pass1) != string(pass2) {
				return "", "", fmt.Errorf("passphrases do not match")
			}
			passphrase = string(pass1)
		}
	}

	return token, passphrase, nil
}

func EncryptKms(ctx context.Context, keyName string, plaintext string) string {
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to load SDK config")
	}

	kmsClient := kms.NewFromConfig(cfg)

	// Call KMS Encrypt API
	result, err := kmsClient.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     &keyName,
		Plaintext: []byte(plaintext),
	})
	if err != nil {
		log.Fatal().Err(err).Msg("failed to encrypt text")
	}

	return base64.StdEncoding.EncodeToString(result.CiphertextBlob)
}

func main() {
	token, passphrase, err := AskCredentials()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if passphrase != "" {
		token, err = unsealing.EncryptWithPassphrase(token, passphrase)
		if err != nil {
			log.Fatal().Err(err).Msg("could not encrypt token with age")
		}
	}

	ctx := context.Background()

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter KMS key name or alias: ")
	keyName, err := reader.ReadString('\n')
	if err != nil {
		log.Fatal().Err(err).Msgf("failed to read KMS key")
	}

	keyName = strings.TrimSpace(keyName)

	kmsEncrypted := EncryptKms(ctx, keyName, token)
	fmt.Println(kmsEncrypted)
}
