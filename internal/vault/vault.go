package vault

import (
	"context"
	"fmt"
	"net/http"
)

type Client interface {
	GetSealedStatus(ctx context.Context, instance string) (*SealedStatus, error)
	// Unseal submits an unseal key and returns the resulting seal status.
	Unseal(ctx context.Context, instance string, unsealKey string) (*SealedStatus, error)
	ResetUnseal(ctx context.Context, instance string) error
}

type AuthMethod interface {
	// Authenticate returns a token that can be used for requests against Vault.
	Authenticate(client *http.Client) (string, error)
	// Cleanup discards the token returned by Authenticate and revokes it, if it was created by the AuthMethod.
	Cleanup(client *http.Client) error
}

type SealedStatus struct {
	Sealed      bool   `json:"sealed,omitempty"`
	Threshold   int    `json:"t"`
	Progress    int    `json:"progress"`
	ClusterName string `json:"cluster_name,omitempty"`
	ClusterId   string `json:"cluster_id,omitempty"`
	Version     string `json:"version"`
}

func (s *SealedStatus) String() string {
	return fmt.Sprintf("Sealed: %t, clusterName: %s, clusterId: %s, version: %s", s.Sealed, s.ClusterName, s.ClusterId, s.Version)
}

type ReadVaultKv2Request struct {
	MountPath  string
	SecretPath string
	SecretKey  string
}

type TransitDecryptRequest struct {
	MountPath         string
	EncryptionKeyName string
	Ciphertext        string
}
