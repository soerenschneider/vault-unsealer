# Configuration

vault-unsealer is configured using a configuration file which is passed via the `-conf` parameter.

It's possible to configure multiple clusters or just a single cluster. Have a look at the following example.

## Example Configuration
```yaml
---
clusters:
  - endpoints:
      - https://vault-1.soeren.cloud:8200
      - https://vault-2.soeren.cloud:8200
      - https://vault-3.soeren.cloud:8200
    cache_unseal_key: true
    check_interval_s: 60
    unseal_key_impl: vault-transit
    unseal_key_config:
      vault_auth_type: approle
      vault_auth_config:
        role_id: yyy
        secret_id: xxx
        approle_mount: approle
      vault_endpoint: https://prd.vault.soeren.cloud
      vault_transit_mount_path: transit_vault_unsealer
      vault_transit_key_name: prod
      vault_transit_ciphertext: cipher
```

## Field Reference

### Clusters

The 'clusters' section configures one or more clusters and the listen address of the prometheus metrics handler.

| Field Name       | Description                                                                                          | YAML Key            | Data Type        | Optional |
|------------------|------------------------------------------------------------------------------------------------------|---------------------|------------------|----------|
| `Clusters`       | An array of `ClusterConfig` objects representing the configuration for unseal clusters.              | `"clusters"`        | Array of objects | No       |
| `PrometheusAddr` | The address of Prometheus for monitoring purposes. If not specified, the default (":9132") is used.  | `"prometheus_addr"` | String           | Yes      |

### ClusterConfig

| Field Name               | Description                                                                                                                                                                      | YAML Key               | Data Type           | Optional |
|--------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|------------------------|---------------------|----------|
| `Endpoints`              | An array of all Vault instances' URLs belonging to the cluster.                                                                                                                  | `"endpoints"`          | Array of strings    | No       |
| `VerifyClusterId`        | The cluster ID for verification purposes.                                                                                                                                        | `"verify_cluster_id"`  | String              | Yes      |
| `CacheUnsealKey`         | A boolean flag indicating whether to cache the unseal key for reliability in case the complete cluster is down at the same time (should not be likely with true HA deployments). | `"cache_unseal_key"`   | Boolean             | No       |
| `CheckIntervalSeconds`   | The interval in seconds at which to check each instance's status.                                                                                                                | `"check_interval_s"`   | Integer             | No       |
| `RetrieveConfig`         | A map containing configuration settings for retrieving the unseal key.                                                                                                           | `"unseal_key_config"`  | Map (String to Any) | Yes      |
| `RetrieveImpl`           | Denotes which retrieve implementation should be built. Has to be one of [vault-transit, vault-kv2, static]                                                                       | `"unseal_key_impl"`    | String              | No       |

### Retrieving the unseal key

#### KV2
| Field Name           | Description                                                             | YAML Key                  | Data Type           | Optional       |
|----------------------|-------------------------------------------------------------------------|---------------------------|---------------------|----------------|
| `VaultAuthType`      | The authentication type for connecting to Vault.                        | `"vault_auth_type"`       | String              | No             |
| `VaultAuthConfig`    | A map containing configuration settings for Vault authentication.       | `"vault_auth_config"`     | Map (String to Any) | No             |
| `VaultEndpoint`      | The URL endpoint for the Vault server.                                  | `"vault_endpoint"`        | String (HTTP URL)   | No             |
| `VaultKv2MountPath`  | The mount path for the KV2 secret engine in Vault.                      | `"vault_kv2_mount_path"`  | String              | Yes            |
| `VaultKv2SecretPath` | The path to the KV2 secret in Vault.                                    | `"vault_kv2_secret_path"` | String              | Yes            |
| `VaultKv2SecretKey`  | The key for accessing a specific secret within the KV2 secret in Vault. | `"vault_kv2_secret_key"`  | String              | Yes            |

#### Transit
| Field Name                   | Description                                                       | YAML Key                          | Data Type            | Optional        |
|------------------------------|-------------------------------------------------------------------|-----------------------------------|----------------------|-----------------|
| `VaultAuthType`              | The authentication type for connecting to Vault.                  | `"vault_auth_type"`               | String               | No              |
| `VaultAuthConfig`            | A map containing configuration settings for Vault authentication. | `"vault_auth_config"`             | Map (String to Any)  | Yes             |
| `VaultEndpoint`              | The URL endpoint for the Vault server.                            | `"vault_endpoint"`                | String (HTTP URL)    | No              |
| `VaultTransitMountPath`      | The mount path for the Vault Transit secret engine.               | `"vault_transit_mount_path"`      | String               | Yes             |
| `VaultTransitKeyName`        | The name of the encryption key used in Vault Transit.             | `"vault_transit_key_name"`        | String               | No              |
| `VaultTransitCiphertextFile` | The path to a file containing Vault Transit ciphertext.           | `"vault_transit_ciphertext_file"` | String (File Path)   | Yes             |
| `VaultTransitCiphertext`     | Vault Transit ciphertext to be used directly.                     | `"vault_transit_ciphertext"`      | String               | Yes             |

### Authentication Strategies

#### Approle Auth
| Field Name         | Description                                      | YAML Key              | Data Type          | Optional  |
|--------------------|--------------------------------------------------|-----------------------|--------------------|-----------|
| `RoleId`           | The RoleID for the AppRole authentication.       | `"role_id"`           | String             | No        |
| `SecretId`         | The SecretID for the AppRole authentication.     | `"secret_id"`         | String             | Yes       |
| `SecretIdFile`     | The path to a file containing the SecretID.      | `"secret_id_file"`    | String (File Path) | Yes       |
| `ApproleMountPath` | The mount path for the AppRole authentication.   | `"approle_mount"`     | String             | Yes       |

#### Token Auth 

Using token auth is not recommended.

| Field Name | Description                                                | YAML Key  | Data Type | Optional |
|------------|------------------------------------------------------------|-----------|-----------|----------|
| `Token`    | The authentication token for token-based authentication.   | `"token"` | String    | No       |
