terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.1.0"
    }
    local = {
      source = "hashicorp/local"
    }
  }
}