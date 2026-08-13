#!/bin/bash
set -euo pipefail
# AZ-SECOPS-003: Create a diagnostic setting on a critical resource exporting to an approved destination
# Usage: ./fix_az_secops_003.sh <resource-id> <workspace-resource-id> [setting-name]
RESOURCE_ID="${1:-}"
WORKSPACE_ID="${2:-}"
SETTING_NAME="${3:-central-security-export}"
if [ -z "$RESOURCE_ID" ] || [ -z "$WORKSPACE_ID" ]; then
  echo "Usage: $0 <resource-id> <workspace-resource-id> [setting-name]"
  echo "  workspace-resource-id must be an organisation-approved central destination."
  exit 1
fi
echo "Creating diagnostic setting '$SETTING_NAME' on resource: $RESOURCE_ID..."
az monitor diagnostic-settings create \
  --name "$SETTING_NAME" \
  --resource "$RESOURCE_ID" \
  --workspace "$WORKSPACE_ID" \
  --logs '[{"categoryGroup":"allLogs","enabled":true}]'
echo "Diagnostic setting created on: $RESOURCE_ID"
