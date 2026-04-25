#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-001 — Service Principal Assigned Owner Role at Subscription Scope
# Usage: ./fix_az_idn_001.sh <subscription-id> <principal-id>
# Severity: HIGH
#
# This script removes the Owner role from the service principal at subscription scope.
# You will need to assign a least-privilege replacement role manually afterwards.

set -e

SUBSCRIPTION_ID=$1
PRINCIPAL_ID=$2

if [ -z "$SUBSCRIPTION_ID" ] || [ -z "$PRINCIPAL_ID" ]; then
  echo "Usage: $0 <subscription-id> <principal-id>"
  exit 1
fi

SCOPE="/subscriptions/$SUBSCRIPTION_ID"
OWNER_ROLE="Owner"

echo "Finding Owner role assignment for principal $PRINCIPAL_ID at subscription scope..."

ASSIGNMENT_ID=$(az role assignment list \
  --scope "$SCOPE" \
  --assignee "$PRINCIPAL_ID" \
  --role "$OWNER_ROLE" \
  --query "[0].id" \
  --output tsv)

if [ -z "$ASSIGNMENT_ID" ]; then
  echo "No Owner role assignment found for principal $PRINCIPAL_ID — already remediated."
  exit 0
fi

echo "Deleting role assignment: $ASSIGNMENT_ID"

az role assignment delete \
  --ids "$ASSIGNMENT_ID"

echo ""
echo "✅ Remediation complete — Owner role removed from $PRINCIPAL_ID."
echo "⚠️  ACTION REQUIRED: Assign a least-privilege replacement role to the service principal."
echo "    Example: az role assignment create --assignee $PRINCIPAL_ID --role Contributor --scope $SCOPE"
