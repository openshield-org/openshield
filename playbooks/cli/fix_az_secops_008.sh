#!/bin/bash
set -euo pipefail
# AZ-SECOPS-008: List Sentinel data connectors for a workspace to identify and repair an unhealthy connector
# Usage: ./fix_az_secops_008.sh <resource-group> <workspace-name>
RESOURCE_GROUP="${1:-}"
WORKSPACE_NAME="${2:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$WORKSPACE_NAME" ]; then
  echo "Usage: $0 <resource-group> <workspace-name>"
  exit 1
fi
echo "Listing Sentinel data connectors for workspace: $WORKSPACE_NAME..."
az sentinel data-connector list --resource-group "$RESOURCE_GROUP" --workspace-name "$WORKSPACE_NAME" -o table
echo ""
echo "Open Microsoft Sentinel > Data connectors in the Azure portal for the connector shown above"
echo "as missing or disconnected, and complete its connection so at least one data type is Enabled."
