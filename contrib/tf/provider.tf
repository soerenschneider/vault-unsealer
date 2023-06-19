terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "3.12.0"
    }
    local = {
      source = "hashicorp/local"
    }
  }
}