#!/bin/bash

set -euo pipefail

REGISTRY_NAME="${1:-}"
RESOURCE_GROUP="${2:-}"

if [[ -z "$REGISTRY_NAME" || -z "$RESOURCE_GROUP" ]]; then
  echo "Usage: $0 <registry-name> <resource-group>"
  exit 1
fi

echo "Disabling anonymous pull for Container Registry: $REGISTRY_NAME (RG: $RESOURCE_GROUP)"
echo "If this registry is intentionally used for public OCI distribution, do not run this script."

az acr update \
  --name "$REGISTRY_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --anonymous-pull-enabled false

echo "Anonymous pull disabled successfully."
