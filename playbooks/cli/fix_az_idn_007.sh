#!/bin/bash
# Playbook: fix_az_idn_007.sh
# Rule: AZ-IDN-007 — Active users with no MFA registered in Entra ID

set -euo pipefail

echo "========================================"
echo " AZ-IDN-007 Remediation Playbook"
echo " Enforce MFA Registration for All Users"
echo "========================================"
echo ""
echo "Users without MFA registered must be required to register before"
echo "they can access resources. Use Conditional Access to enforce this."
echo ""

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <tenant_id>"
  echo ""
  echo "Step 1 — Identify users without MFA via the Graph report"
  echo "  az rest --method GET \\"
  echo "    --url \"https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails\" \\"
  echo "    --query \"value[?isMfaRegistered==\`false\` && isEnabled==\`true\`].userPrincipalName\" \\"
  echo "    --output tsv"
  echo ""
  echo "Step 2 — Create a Conditional Access policy requiring MFA"
  echo "  Navigate to: portal.azure.com"
  echo "  Go to: Entra ID > Protection > Conditional Access > Policies > New policy"
  echo "  Name: Require MFA for all users"
  echo "  Users: All users (exclude break-glass accounts)"
  echo "  Cloud apps: All cloud apps"
  echo "  Grant: Require multi-factor authentication"
  echo "  Enable policy: Report-only first, then On after review"
  echo ""
  echo "Step 3 — Enable the Authentication methods registration campaign"
  echo "  Go to: Entra ID > Protection > Authentication methods > Registration campaign"
  echo "  Enable the campaign to prompt users to register MFA on next sign-in"
  echo ""
  exit 0
fi

TENANT_ID="$1"

echo "Step 1 — Users without MFA registered in tenant $TENANT_ID"
az rest \
  --method GET \
  --url "https://graph.microsoft.com/v1.0/reports/credentialUserRegistrationDetails?%24top=999" \
  --query "value[?isMfaRegistered==\`false\` && isEnabled==\`true\`].{user:userPrincipalName, mfaCapable:isMfaCapable}" \
  --output table 2>/dev/null \
  || echo "Run az login --tenant $TENANT_ID first and ensure Reports.Read.All permission."

echo ""
echo "Step 2 — Create Conditional Access policy to require MFA (Portal only)"
echo "  See: https://learn.microsoft.com/en-us/entra/identity/conditional-access/howto-conditional-access-policy-all-users-mfa"
echo ""
echo "Remediation guidance complete."
echo "Re-run the scanner after the CA policy is in Report-only mode to track progress."
