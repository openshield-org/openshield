#!/bin/bash
set -euo pipefail
# AZ-KV-004: Enable purge protection on an Azure Key Vault
# Usage: ./fix_az_kv_004.sh <resource-group> <vault-name>
RESOURCE_GROUP=$1
VAULT_NAME=$2
if [ -z "$RESOURCE_GROUP" ] || [ -z "$VAULT_NAME" ]; then
  echo "Usage: $0 <resource-group> <vault-name>"
  exit 1
fi
echo "Enabling purge protection on Key Vault: $VAULT_NAME..."
az keyvault update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VAULT_NAME" \
  --enable-purge-protection true
echo "Purge protection enabled for Key Vault: $VAULT_NAME"
echo "Note: Purge protection cannot be disabled once enabled."