#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-015 - Managed identity has privileged subscription role
# Usage: ./fix_az_idn_015.sh <role-assignment-resource-id>

set -euo pipefail

ASSIGNMENT_ID=${1:-}
if [ -z "$ASSIGNMENT_ID" ]; then
  echo "Usage: $0 <role-assignment-resource-id>"
  exit 1
fi

az account show --output none
az role assignment list --query "[?id=='$ASSIGNMENT_ID'].{principalId:principalId,role:roleDefinitionName,scope:scope}" \
  --output table
echo "WARNING: Confirm the workload has a narrower replacement assignment before removal."
read -r -p "Type APPLY to delete this privileged assignment: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az role assignment delete --ids "$ASSIGNMENT_ID"
echo "Privileged subscription-scope assignment removed."
