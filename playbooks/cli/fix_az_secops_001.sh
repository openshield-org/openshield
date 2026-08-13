#!/bin/bash
set -euo pipefail
# AZ-SECOPS-001: Export subscription Activity Log to an approved central Log Analytics workspace
# Usage: ./fix_az_secops_001.sh <setting-name> <location> <workspace-resource-id>
SETTING_NAME="${1:-}"
LOCATION="${2:-}"
WORKSPACE_ID="${3:-}"
if [ -z "$SETTING_NAME" ] || [ -z "$LOCATION" ] || [ -z "$WORKSPACE_ID" ]; then
  echo "Usage: $0 <setting-name> <location> <workspace-resource-id>"
  echo "  workspace-resource-id must be an organisation-approved central destination."
  exit 1
fi
echo "Creating subscription Activity Log diagnostic setting: $SETTING_NAME..."
az monitor diagnostic-settings subscription create \
  --name "$SETTING_NAME" \
  --location "$LOCATION" \
  --workspace "$WORKSPACE_ID" \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true},{"category":"ServiceHealth","enabled":true},{"category":"Alert","enabled":true},{"category":"Recommendation","enabled":true}]'
echo "Activity Log diagnostic setting created: $SETTING_NAME -> $WORKSPACE_ID"
