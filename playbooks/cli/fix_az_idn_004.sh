#!/bin/bash
# Playbook: fix_az_idn_004.sh
# Rule: AZ-IDN-004 — No Privileged Identity Management for admin roles

set -euo pipefail

echo "========================================"
echo " AZ-IDN-004 Remediation Playbook"
echo " Enable PIM for Admin Roles"
echo "========================================"
echo ""
echo "NOTE: PIM must be configured manually in the Azure Portal."
echo "Automated PIM assignment requires Azure AD Premium P2 license."
echo ""
echo "Step 1 — Verify PIM is available"
echo "  Navigate to: portal.azure.com"
echo "  Go to: Entra ID > Identity Governance > Privileged Identity Management"
echo "  Confirm your tenant has Azure AD Premium P2 licensing"
echo ""
echo "Step 2 — Configure PIM for each admin role"
echo "  Go to: PIM > Azure AD roles > Roles"
echo "  For each role listed below, click the role and select Settings:"
echo "    - Global Administrator"
echo "    - Privileged Role Administrator"
echo "    - Security Administrator"
echo "    - Exchange Administrator"
echo "    - SharePoint Administrator"
echo "    - Conditional Access Administrator"
echo "    - Helpdesk Administrator"
echo "    - User Administrator"
echo "    - Application Administrator"
echo "    - Cloud Application Administrator"
echo ""
echo "Step 3 — Configure each role with:"
echo "  - Activation maximum duration: 8 hours or less"
echo "  - Require MFA on activation: Enabled"
echo "  - Require justification on activation: Enabled"
echo "  - Require approval for activation: Enabled (for Global Admin)"
echo ""
echo "Step 4 — Convert permanent assignments to eligible"
echo "  Go to: PIM > Azure AD roles > Assignments"
echo "  For each permanent admin assignment:"
echo "  Click the assignment > Update > Change to Eligible"
echo ""

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <tenant_id>"
  echo "Running in guidance-only mode — no tenant ID provided"
  exit 0
fi

TENANT_ID="$1"

echo "Step 5 — Verify PIM eligible assignments via CLI"
echo "Checking existing role eligibility schedules for tenant $TENANT_ID..."
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules" \
  --query "value[].{role:roleDefinitionId, principal:principalId, status:status}" \
  --output table 2>/dev/null || echo "Run az login first and ensure RoleManagement.Read.Directory permission."

echo ""
echo "Remediation guidance complete."
echo "Re-run the scanner after configuring PIM to verify compliance."
