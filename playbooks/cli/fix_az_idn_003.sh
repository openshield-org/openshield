#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-003 — Guest user access enabled without restriction in Entra ID
# Usage: ./fix_az_idn_003.sh
# Severity: MEDIUM
#
# Prerequisites:
#   - Azure CLI logged in with a Global Administrator or User Administrator role
#   - Microsoft Graph PowerShell or az rest permissions

set -e

echo "Restricting guest user invitations to admins only..."

az rest \
  --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/policies/authorizationPolicy" \
  --headers "Content-Type=application/json" \
  --body '{
    "allowInvitesFrom": "adminsAndGuestInviters"
  }'

echo "✅ Guest invitation policy updated."
echo "   allowInvitesFrom is now set to: adminsAndGuestInviters"
echo "⚠️  Only users assigned to the Guest Inviter role or admins can now invite external users."
echo "⚠️  Review existing guest accounts to ensure they are still required."
