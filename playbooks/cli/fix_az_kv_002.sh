#!/bin/bash

# Fix AZ-KV-002: Disable public network access on Key Vault

VAULT_NAME=$1
RESOURCE_GROUP=$2

if [ -z "$VAULT_NAME" ] || [ -z "$RESOURCE_GROUP" ]; then
  echo "Usage: $0 <vault-name> <resource-group>"
  exit 1
fi

echo "Disabling public network access for Key Vault: $VAULT_NAME"

az keyvault update \
  --name "$VAULT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --public-network-access Disabled

if [ $? -eq 0 ]; then
  echo "Public network access disabled successfully."
  echo "Next step: Configure a private endpoint for full security."
else
  echo "Failed to update Key Vault."
fi