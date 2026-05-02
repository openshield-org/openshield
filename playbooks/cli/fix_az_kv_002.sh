#!/bin/bash

set -euo pipefail

VAULT_NAME="${1:-}"
RESOURCE_GROUP="${2:-}"

if [[ -z "$VAULT_NAME" || -z "$RESOURCE_GROUP" ]]; then
  echo "Usage: $0 <vault-name> <resource-group>"
  exit 1
fi

echo "Disabling public network access for Key Vault: $VAULT_NAME (RG: $RESOURCE_GROUP)"

az keyvault update \
  --name "$VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --public-network-access Disabled

echo "Public network access disabled successfully."
echo "Next step: Configure a private endpoint for full protection."