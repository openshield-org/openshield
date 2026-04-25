#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-STOR-002 — Storage Account Allows HTTP Traffic (Not HTTPS-Only)
# Usage: ./fix_az_stor_002.sh <resource-group> <storage-account-name>
# Severity: HIGH

set -e

RESOURCE_GROUP=$1
RESOURCE_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name>"
  exit 1
fi

echo "Enabling HTTPS-only (secure transfer required) on: $RESOURCE_NAME"

az storage account update \
  --name "$RESOURCE_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --https-only true

echo "✅ Remediation complete for $RESOURCE_NAME — HTTPS-only traffic is now enforced."
