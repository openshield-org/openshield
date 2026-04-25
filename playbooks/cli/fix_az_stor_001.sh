#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-STOR-001 — Public Blob Access Enabled on Storage Account
# Usage: ./fix_az_stor_001.sh <resource-group> <storage-account-name>
# Severity: HIGH

set -e

RESOURCE_GROUP=$1
RESOURCE_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name>"
  exit 1
fi

echo "Disabling public blob access on storage account: $RESOURCE_NAME"

az storage account update \
  --name "$RESOURCE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --allow-blob-public-access false

echo "✅ Remediation complete for $RESOURCE_NAME — public blob access is now disabled."
