#!/bin/bash
# Playbook: fix_az_idn_005.sh
# Rule: AZ-IDN-005 — Guest users with high privilege roles in Entra ID

set -euo pipefail

echo "========================================"
echo " AZ-IDN-005 Remediation Playbook"
echo " Remove High Privilege Roles from Guest Users"
echo "========================================"
echo ""
echo "Guest accounts must not hold privileged roles in Entra ID."
echo "External identities with admin rights represent an uncontrolled risk."
echo ""

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <tenant_id> [user_principal_name]"
  echo ""
  echo "Step 1 — List all guest users with role assignments"
  echo "  az rest --method GET \\"
  echo "    --url \"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\\\$expand=principal\" \\"
  echo "    --query \"value[?principal.userType=='Guest'].{user:principal.userPrincipalName, role:roleDefinitionId}\""
  echo ""
  echo "Step 2 — Remove the role assignment"
  echo "  az rest --method DELETE \\"
  echo "    --url \"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/<assignment-id>\""
  echo ""
  exit 0
fi

TENANT_ID="$1"

echo "Step 1 — Fetching guest role assignments in tenant $TENANT_ID"
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$expand=principal" \
  --query "value[?principal.userType=='Guest'].{user:principal.userPrincipalName, assignmentId:id, roleId:roleDefinitionId}" \
  --output table 2>/dev/null \
  || echo "Run az login --tenant $TENANT_ID first and ensure RoleManagement.Read.Directory permission."

if [[ $# -ge 2 ]]; then
  UPN="$2"
  echo ""
  echo "Step 2 — Looking up role assignments for $UPN"
  az rest \
    --method GET \
    --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=principal/userPrincipalName eq '$UPN'" \
    --output json 2>/dev/null \
    || echo "Could not fetch assignments for $UPN"
fi

echo ""
echo "To remove an assignment:"
echo "  az rest --method DELETE \\"
echo "    --url \"https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments/<assignment-id>\""
echo ""
echo "Remediation guidance complete."
echo "Re-run the scanner after removing assignments to verify compliance."
