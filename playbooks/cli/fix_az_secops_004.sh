#!/bin/bash
set -euo pipefail
# AZ-SECOPS-004: Increase Storage Account log-export retention to the organisation minimum
# Usage: ./fix_az_secops_004.sh <resource-id> <setting-name> <minimum-retention-days>
RESOURCE_ID="${1:-}"
SETTING_NAME="${2:-}"
RETENTION_DAYS="${3:-}"
if [ -z "$RESOURCE_ID" ] || [ -z "$SETTING_NAME" ] || [ -z "$RETENTION_DAYS" ]; then
  echo "Usage: $0 <resource-id> <setting-name> <minimum-retention-days>"
  exit 1
fi
echo "Setting Storage Account log retention to ${RETENTION_DAYS} days on: $SETTING_NAME..."
az monitor diagnostic-settings update \
  --name "$SETTING_NAME" \
  --resource "$RESOURCE_ID" \
  --logs "[{\"categoryGroup\":\"allLogs\",\"enabled\":true,\"retentionPolicy\":{\"enabled\":true,\"days\":${RETENTION_DAYS}}}]"
echo "Retention updated to ${RETENTION_DAYS} days on: $SETTING_NAME"
