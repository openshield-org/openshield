#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-STOR-005 — Storage Account Not Using Geo-Redundant Replication
# Usage: ./fix_az_stor_005.sh <resource-group> <storage-account-name> [target-sku]
# Severity: MEDIUM

set -euo pipefail

RESOURCE_GROUP="${1:-}"
RESOURCE_NAME="${2:-}"
TARGET_SKU="${3:-Standard_GRS}"

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name> [target-sku]"
  echo "  target-sku defaults to Standard_GRS"
  echo "  Valid geo-redundant options: Standard_GRS, Standard_RAGRS, Standard_GZRS, Standard_RAGZRS"
  exit 1
fi

case "$TARGET_SKU" in
  Standard_GRS|Standard_RAGRS|Standard_GZRS|Standard_RAGZRS)
    ;;
  *)
    echo "Error: '$TARGET_SKU' is not a supported geo-redundant SKU."
    echo "Valid options: Standard_GRS, Standard_RAGRS, Standard_GZRS, Standard_RAGZRS"
    exit 1
    ;;
esac

echo "Checking current SKU for $RESOURCE_NAME..."
CURRENT_SKU=$(az storage account show \
  --name "$RESOURCE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "sku.name" \
  --output tsv)
echo "Current SKU: $CURRENT_SKU"

echo "Remediating AZ-STOR-005 for $RESOURCE_NAME — updating replication to $TARGET_SKU..."
az storage account update \
  --name "$RESOURCE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --sku "$TARGET_SKU"

echo "Updated SKU for $RESOURCE_NAME:"
az storage account show \
  --name "$RESOURCE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --query "sku.name" \
  --output tsv

echo "Remediation complete for $RESOURCE_NAME — replication is now $TARGET_SKU."
