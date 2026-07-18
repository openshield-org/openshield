#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-012 - App Registration enables OAuth implicit grant
# Usage: ./fix_az_idn_012.sh <application-object-id>

set -euo pipefail

OBJECT_ID=${1:-}
if [ -z "$OBJECT_ID" ]; then
  echo "Usage: $0 <application-object-id>"
  exit 1
fi

az account show --output none
echo "WARNING: Existing implicit-flow clients must migrate to authorization code with PKCE first."
read -r -p "Type APPLY to disable implicit token issuance: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az rest --method PATCH \
  --uri "https://graph.microsoft.com/v1.0/applications/$OBJECT_ID" \
  --headers "Content-Type=application/json" \
  --body '{"web":{"implicitGrantSettings":{"enableAccessTokenIssuance":false,"enableIdTokenIssuance":false}}}'
echo "Implicit access-token and ID-token issuance disabled."
