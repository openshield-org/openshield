#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-014 - Multi-tenant app lacks application-instance property lock
# Usage: ./fix_az_idn_014.sh <application-object-id>

set -euo pipefail

OBJECT_ID=${1:-}
if [ -z "$OBJECT_ID" ]; then
  echo "Usage: $0 <application-object-id>"
  exit 1
fi

az account show --output none
echo "WARNING: Property lock prevents tenant service-principal instances from changing sensitive properties."
read -r -p "Type APPLY to enable the full sensitive-property lock: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" \
  --headers "Content-Type=application/json" \
  --body '{"servicePrincipalLockConfiguration":{"isEnabled":true,"allProperties":true}}'
echo "Application-instance sensitive-property lock enabled."
