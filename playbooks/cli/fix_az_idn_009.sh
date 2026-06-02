#!/bin/bash
# Playbook: fix_az_idn_009.sh
# Rule: AZ-IDN-009 — No activity log alert for role assignment changes

set -euo pipefail

echo "========================================"
echo " AZ-IDN-009 Remediation Playbook"
echo " Create Activity Log Alert for Role Assignment Changes"
echo "========================================"
echo ""
echo "An alert must exist for Microsoft.Authorization/roleAssignments/write"
echo "so that privilege escalation is detected in real time."
echo ""

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <subscription_id> <resource_group> <action_group_id>"
  echo ""
  echo "Step 1 — Confirm an action group exists (or create one)"
  echo "  az monitor action-group list --output table"
  echo "  az monitor action-group create \\"
  echo "    --name 'SecurityAlerts' \\"
  echo "    --resource-group <rg-name> \\"
  echo "    --short-name 'SecAlerts' \\"
  echo "    --email-receiver name='on-call' email='security@example.com'"
  echo ""
  echo "Step 2 — Create the activity log alert"
  echo "  az monitor activity-log alert create \\"
  echo "    --name 'Alert-RoleAssignment-Write' \\"
  echo "    --resource-group <rg-name> \\"
  echo "    --scope /subscriptions/<subscription-id> \\"
  echo "    --condition category=Administrative \\"
  echo "      operationName=Microsoft.Authorization/roleAssignments/write \\"
  echo "    --action-group <action-group-id>"
  echo ""
  exit 0
fi

SUBSCRIPTION_ID="$1"
RESOURCE_GROUP="$2"
ACTION_GROUP_ID="$3"
ALERT_NAME="Alert-RoleAssignment-Write"

echo "Step 1 — Checking existing activity log alerts..."
az monitor activity-log alert list \
  --subscription "$SUBSCRIPTION_ID" \
  --output table \
  || { echo "Could not list alerts. Run az login first."; exit 1; }

echo ""
echo "Step 2 — Creating alert: $ALERT_NAME"
az monitor activity-log alert create \
  --name "$ALERT_NAME" \
  --resource-group "$RESOURCE_GROUP" \
  --subscription "$SUBSCRIPTION_ID" \
  --scope "/subscriptions/$SUBSCRIPTION_ID" \
  --condition \
    category=Administrative \
    operationName="Microsoft.Authorization/roleAssignments/write" \
  --action-group "$ACTION_GROUP_ID" \
  --description "Alerts when a role assignment is created or modified in the subscription."

echo ""
echo "Alert '$ALERT_NAME' created successfully."
echo "Re-run the scanner to verify compliance."
