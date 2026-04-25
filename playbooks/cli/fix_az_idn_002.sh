#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-002 — No MFA Enforced on Admin Accounts via Conditional Access
# Usage: ./fix_az_idn_002.sh
# Severity: HIGH
#
# This script creates a Conditional Access policy via Microsoft Graph API
# that requires MFA for all users assigned administrator directory roles.
# Prerequisites:
#   - az login with a Global Administrator or Conditional Access Administrator account
#   - Microsoft Graph PowerShell or Graph API access

set -e

echo "Creating Conditional Access policy to enforce MFA for administrators..."
echo ""
echo "This operation requires Global Administrator or Conditional Access Administrator privileges."
echo ""

# Prompt for confirmation
read -p "Proceed with creating the MFA enforcement policy? [y/N] " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

# Acquire a Graph API token
TOKEN=$(az account get-access-token \
  --resource https://graph.microsoft.com \
  --query accessToken \
  --output tsv)

POLICY_BODY='{
  "displayName": "OpenShield: Require MFA for Administrators",
  "state": "enabled",
  "conditions": {
    "users": {
      "includeRoles": [
        "62e90394-69f5-4237-9190-012177145e10",
        "e8611ab8-c189-46e8-94e1-60213ab1f814",
        "194ae4cb-b126-40b2-bd5b-6091b380977d",
        "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
      ]
    },
    "applications": {
      "includeApplications": ["All"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}'

RESPONSE=$(curl -s -X POST \
  "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "$POLICY_BODY")

POLICY_ID=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('id',''))" 2>/dev/null)

if [ -n "$POLICY_ID" ]; then
  echo "✅ Remediation complete — Conditional Access policy created: $POLICY_ID"
else
  echo "❌ Policy creation failed. Response:"
  echo "$RESPONSE"
  exit 1
fi
