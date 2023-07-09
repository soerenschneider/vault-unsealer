package vault

import (
	"context"
	"fmt"
	"net/http"
)

type Client interface {
	GetSealedStatus(ctx context.Context, instance string) (*SealedStatus, error)
	Unseal(ctx context.Context, instance string, unsealKey string) error
}

type AuthMethod interface {
	Authenticate(client *http.Client) (string, error)
	Cleanup() error
}

type SealedStatus struct {
	Sealed      bool   `json:"sealed,omitempty"`
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
