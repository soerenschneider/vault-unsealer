resource "vault_mount" "transit" {
  path                      = "transit"
  type                      = "transit"
  description               = "Vault unseal"
  default_lease_ttl_seconds = 3600
  max_lease_ttl_seconds     = 3600
}

resource "vault_transit_secret_backend_key" "key" {
  backend    = vault_mount.transit.path
  name       = "vault-unseal"
  exportable = false
  type       = "aes256-gcm96"
}

resource "vault_mount" "kv" {
  path        = "secret-kv2"
  type        = "kv-v2"
  description = "Secret kv mount"
}

resource "vault_kv_secret_v2" "example" {
  mount                      = vault_mount.kv.path
  name                       = "vault-unseal"
  cas                        = 1
  delete_all_versions        = true
  data_json                  = jsonencode({
      unseal_key       = "4x8GAv+MMBcBwFkkRG1tBSFD9DGC7/V/t2y+rwMssVQ=",
  })
}