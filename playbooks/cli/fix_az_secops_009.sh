#!/bin/bash
set -euo pipefail
# AZ-SECOPS-009: Create an enabled, High-severity Sentinel scheduled analytics rule for a detection use case
# Usage: ./fix_az_secops_009.sh <resource-group> <workspace-name> <use-case-name> <kql-query>
RESOURCE_GROUP="${1:-}"
WORKSPACE_NAME="${2:-}"
USE_CASE_NAME="${3:-}"
KQL_QUERY="${4:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$WORKSPACE_NAME" ] || [ -z "$USE_CASE_NAME" ] || [ -z "$KQL_QUERY" ]; then
  echo "Usage: $0 <resource-group> <workspace-name> <use-case-name> <kql-query>"
  exit 1
fi
echo "Creating High-severity Sentinel analytics rule for use case: $USE_CASE_NAME..."
az sentinel alert-rule create \
  --resource-group "$RESOURCE_GROUP" \
  --workspace-name "$WORKSPACE_NAME" \
  --kind Scheduled \
  --severity High \
  --display-name "$USE_CASE_NAME" \
  --enabled true \
  --query "$KQL_QUERY" \
  --query-frequency PT1H \
  --query-period PT1H \
  --trigger-operator GreaterThan \
  --trigger-threshold 0
echo "Analytics rule created for use case: $USE_CASE_NAME"
