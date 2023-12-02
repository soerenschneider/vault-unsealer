#!/usr/bin/env bash

set -e
set -u

TRANSIT_PATH="transit_vault_unsealer"

unseal_key_raw="$(pass vault/prd/unseal-key-1)"
unseal_key_encoded=$(echo -n $unseal_key_raw | base64 -w0)

vault write "${TRANSIT_PATH}/encrypt/prod" \
    plaintext="${unseal_key_encoded}"
