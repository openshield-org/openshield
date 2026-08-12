#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-STOR-006 — Storage account HTTPS-only enforcement disabled
# Usage: ./fix_az_stor_006.sh <resource-group> <storage-account-name>
# Severity: HIGH

set -euo pipefail

RESOURCE_GROUP="${1:-}"
STORAGE_ACCOUNT="${2:-}"

if [ -z "$RESOURCE_GROUP" ] || [ -z "$STORAGE_ACCOUNT" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name>"
  exit 1
fi

echo "Enabling HTTPS-only enforcement for storage account: ${STORAGE_ACCOUNT} (rg: ${RESOURCE_GROUP})"

# Azure CLI command to enable HTTPS-only (secure transfer)
az storage account update \
  --name "${STORAGE_ACCOUNT}" \
  --resource-group "${RESOURCE_GROUP}" \
  --https-only true \
  --output json

echo "Verification: current supportsHttpsTrafficOnly value:"
az storage account show \
  --name "${STORAGE_ACCOUNT}" \
  --resource-group "${RESOURCE_GROUP}" \
  --query "supportsHttpsTrafficOnly" \
  --output tsv

echo "Remediation complete: HTTPS-only enforcement enabled for ${STORAGE_ACCOUNT}."
