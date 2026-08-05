#!/bin/bash

set -euo pipefail

REGISTRY_NAME="${1:-}"
RESOURCE_GROUP="${2:-}"

if [[ -z "$REGISTRY_NAME" || -z "$RESOURCE_GROUP" ]]; then
  echo "Usage: $0 <registry-name> <resource-group>"
  exit 1
fi

echo "Disabling public network access for Container Registry: $REGISTRY_NAME (RG: $RESOURCE_GROUP)"

az acr update \
  --name "$REGISTRY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --public-network-enabled false

echo "Public network access disabled successfully."
echo "Next step: Configure a private endpoint if the registry needs to be reachable from a VNet."
