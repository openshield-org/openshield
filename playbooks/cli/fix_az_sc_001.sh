#!/bin/bash

set -euo pipefail

REGISTRY_NAME="${1:-}"
RESOURCE_GROUP="${2:-}"

if [[ -z "$REGISTRY_NAME" || -z "$RESOURCE_GROUP" ]]; then
  echo "Usage: $0 <registry-name> <resource-group>"
  exit 1
fi

echo "Disabling admin user for Container Registry: $REGISTRY_NAME (RG: $RESOURCE_GROUP)"

az acr update \
  --name "$REGISTRY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --admin-enabled false

echo "Admin user disabled successfully."
echo "Next step: Authenticate with Azure AD identities or a managed identity instead."
