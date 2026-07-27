#!/bin/bash

set -euo pipefail

ACCOUNT_NAME="${1:-}"
RESOURCE_GROUP="${2:-}"
RETENTION_DAYS="${3:-30}"

if [[ -z "$ACCOUNT_NAME" || -z "$RESOURCE_GROUP" ]]; then
  echo "Usage: $0 <storage-account-name> <resource-group> [retention-days]"
  exit 1
fi

echo "Enabling blob versioning and soft delete for storage account: $ACCOUNT_NAME (RG: $RESOURCE_GROUP)"

az storage account blob-service-properties update \
  --account-name "$ACCOUNT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-versioning true \
  --enable-delete-retention true \
  --delete-retention-days "$RETENTION_DAYS"

echo "Blob versioning and soft delete ($RETENTION_DAYS-day retention) enabled successfully."
