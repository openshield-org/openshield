#!/bin/bash
set -euo pipefail
# AZ-SECOPS-010: Create a monitored Azure Monitor action group so security alerts reach a responder
# Usage: ./fix_az_secops_010.sh <resource-group> <action-group-name> <short-name> <receiver-name> <email>
RESOURCE_GROUP="${1:-}"
ACTION_GROUP_NAME="${2:-}"
SHORT_NAME="${3:-}"
RECEIVER_NAME="${4:-}"
EMAIL="${5:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$ACTION_GROUP_NAME" ] || [ -z "$SHORT_NAME" ] || [ -z "$RECEIVER_NAME" ] || [ -z "$EMAIL" ]; then
  echo "Usage: $0 <resource-group> <action-group-name> <short-name> <receiver-name> <email>"
  exit 1
fi
echo "Creating monitored action group: $ACTION_GROUP_NAME..."
az monitor action-group create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ACTION_GROUP_NAME" \
  --short-name "$SHORT_NAME" \
  --action email "$RECEIVER_NAME" "$EMAIL"
echo "Action group created: $ACTION_GROUP_NAME"
echo "Attach this action group to Defender for Cloud email notifications and/or a Sentinel"
echo "automation rule so both alert sources reach a monitored incident-response destination."
