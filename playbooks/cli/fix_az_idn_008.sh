#!/bin/bash
# Playbook: fix_az_idn_008.sh
# Rule: AZ-IDN-008 — Custom RBAC role with wildcard permissions at subscription scope

set -euo pipefail

echo "========================================"
echo " AZ-IDN-008 Remediation Playbook"
echo " Narrow Custom RBAC Role Wildcard Permissions"
echo "========================================"
echo ""
echo "Custom roles with wildcard actions (*) grant Owner-equivalent permissions."
echo "Replace wildcards with the specific actions the role actually needs."
echo ""

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <subscription_id> [role_name]"
  echo ""
  echo "Step 1 — List all custom roles with wildcard actions"
  echo "  az role definition list --custom-role-only true \\"
  echo "    --query \"[?contains(permissions[0].actions, '*')].{name:roleName, actions:permissions[0].actions}\" \\"
  echo "    --output table"
  echo ""
  echo "Step 2 — Review what the role is actually used for"
  echo "  az role assignment list --role '<role-name>' --all --output table"
  echo ""
  echo "Step 3 — Export the role definition"
  echo "  az role definition show --name '<role-name>' > role.json"
  echo ""
  echo "Step 4 — Edit role.json to replace '*' with specific actions"
  echo "  Use the Azure built-in roles reference to find minimum required actions."
  echo "  See: https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles"
  echo ""
  echo "Step 5 — Update the role definition"
  echo "  az role definition update --role-definition role.json"
  echo ""
  echo "Step 6 — If the role is unused, delete it"
  echo "  az role definition delete --name '<role-name>'"
  echo ""
  exit 0
fi

SUBSCRIPTION_ID="$1"

echo "Step 1 — Custom roles with wildcard actions in subscription $SUBSCRIPTION_ID"
az role definition list \
  --custom-role-only true \
  --scope "/subscriptions/$SUBSCRIPTION_ID" \
  --query "[?contains(permissions[0].actions, '*')].{name:roleName, actions:permissions[0].actions}" \
  --output table \
  || { echo "Could not list role definitions. Run az login first."; exit 1; }

if [[ $# -ge 2 ]]; then
  ROLE_NAME="$2"
  echo ""
  echo "Step 2 — Assignments using role: $ROLE_NAME"
  az role assignment list \
    --role "$ROLE_NAME" \
    --subscription "$SUBSCRIPTION_ID" \
    --all \
    --output table

  echo ""
  echo "Step 3 — Exporting role definition to role_${ROLE_NAME// /_}.json"
  az role definition show \
    --name "$ROLE_NAME" \
    --subscription "$SUBSCRIPTION_ID" \
    > "role_${ROLE_NAME// /_}.json"
  echo "Edit the file, then run: az role definition update --role-definition role_${ROLE_NAME// /_}.json"
fi

echo ""
echo "Remediation guidance complete."
echo "Re-run the scanner after updating role definitions to verify compliance."
