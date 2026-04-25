#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-KV-001 — Key Vault with Soft Delete Disabled
# Usage: ./fix_az_kv_001.sh <resource-group> <key-vault-name>
# Severity: MEDIUM
#
# Note: Enabling soft delete is a one-way operation — it cannot be reversed.
# Once enabled, deleted objects enter a recoverable state for the retention period.

set -e

RESOURCE_GROUP=$1
RESOURCE_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <key-vault-name>"
  exit 1
fi

echo "Enabling soft delete on Key Vault: $RESOURCE_NAME"
echo "⚠️  This operation is irreversible. Soft delete, once enabled, cannot be disabled."
echo ""

read -p "Proceed? [y/N] " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

az keyvault update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$RESOURCE_NAME" \
  --enable-soft-delete true \
  --retention-days 90

echo ""
echo "✅ Remediation complete for $RESOURCE_NAME — soft delete is now enabled (90-day retention)."
echo "Consider also enabling purge protection:"
echo "  az keyvault update --name $RESOURCE_NAME --resource-group $RESOURCE_GROUP --enable-purge-protection true"
