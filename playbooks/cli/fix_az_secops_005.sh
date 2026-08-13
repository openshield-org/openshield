#!/bin/bash
set -euo pipefail
# AZ-SECOPS-005: Add a second log export to an organisation-approved, centrally-owned destination
# Usage: ./fix_az_secops_005.sh <resource-id> <setting-name> <approved-workspace-resource-id>
RESOURCE_ID="${1:-}"
SETTING_NAME="${2:-}"
APPROVED_WORKSPACE_ID="${3:-}"
if [ -z "$RESOURCE_ID" ] || [ -z "$SETTING_NAME" ] || [ -z "$APPROVED_WORKSPACE_ID" ]; then
  echo "Usage: $0 <resource-id> <setting-name> <approved-workspace-resource-id>"
  echo "  approved-workspace-resource-id must NOT be owned by the workload's own resource group."
  exit 1
fi
echo "Adding an approved, centrally-owned destination to diagnostic setting: $SETTING_NAME..."
az monitor diagnostic-settings update \
  --name "$SETTING_NAME" \
  --resource "$RESOURCE_ID" \
  --workspace "$APPROVED_WORKSPACE_ID"
echo "Diagnostic setting $SETTING_NAME now also exports to: $APPROVED_WORKSPACE_ID"
echo "Consider also enabling a Storage Account immutability policy as defence in depth."
