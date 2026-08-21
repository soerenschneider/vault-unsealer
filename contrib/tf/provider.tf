terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.11.0"
    }
    local = {
      source = "hashicorp/local"
    }
  }
}