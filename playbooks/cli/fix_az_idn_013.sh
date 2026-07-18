#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-013 - App Registration uses password credentials
# Usage: ./fix_az_idn_013.sh <application-client-id>

set -euo pipefail

APP_ID=${1:-}
if [ -z "$APP_ID" ]; then
  echo "Usage: $0 <application-client-id>"
  exit 1
fi

az account show --output none
az ad app credential list --id "$APP_ID" --query "[].{type:type,displayName:displayName,endDateTime:endDateTime}" --output table
echo "Migrate the workload to managed identity, workload federation, or a certificate before deleting secrets."
echo "No credential was deleted automatically because doing so can cause an immediate production outage."
