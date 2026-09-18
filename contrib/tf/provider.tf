terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.12.0"
    }
    local = {
      source = "hashicorp/local"
    }
  }
}