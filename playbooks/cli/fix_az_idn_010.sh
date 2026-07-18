#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-010 - App Registration has no owner
# Usage: ./fix_az_idn_010.sh <application-client-id> <owner-object-id>

set -euo pipefail

APP_ID=${1:-}
OWNER_ID=${2:-}
if [ -z "$APP_ID" ] || [ -z "$OWNER_ID" ]; then
  echo "Usage: $0 <application-client-id> <owner-object-id>"
  exit 1
fi

az account show --output none
az ad app show --id "$APP_ID" --query "{appId:appId,displayName:displayName}" --output table
read -r -p "Type APPLY to add owner '$OWNER_ID': " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az ad app owner add --id "$APP_ID" --owner-object-id "$OWNER_ID"
az ad app owner list --id "$APP_ID" --query "[].id" --output table
