#!/bin/bash

set -euo pipefail

REGISTRY_NAME="${1:-}"
RESOURCE_GROUP="${2:-}"
RETENTION_DAYS="${3:-30}"

if [[ -z "$REGISTRY_NAME" || -z "$RESOURCE_GROUP" ]]; then
  echo "Usage: $0 <registry-name> <resource-group> [retention-days]"
  exit 1
fi

echo "Enabling untagged-manifest retention for Container Registry: $REGISTRY_NAME (RG: $RESOURCE_GROUP)"

az acr config retention update \
  --registry "$REGISTRY_NAME" \
  --status enabled \
  --days "$RETENTION_DAYS"

echo "Retention policy enabled ($RETENTION_DAYS days)."
echo "Quarantine policy has no dedicated Azure CLI command and requires the Premium SKU."
echo "Enable it via ARM/Bicep by setting properties.policies.quarantinePolicy.status to 'enabled'."
