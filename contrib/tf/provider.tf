terraform {
  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "5.2.1"
    }
    local = {
      source = "hashicorp/local"
    }
  }
}