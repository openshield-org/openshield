#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-IDN-011 - App Registration uses insecure redirect URI
# Usage: ./fix_az_idn_011.sh <application-client-id>

set -euo pipefail

APP_ID=${1:-}
if [ -z "$APP_ID" ]; then
  echo "Usage: $0 <application-client-id>"
  exit 1
fi

az account show --output none
echo "Current redirect URIs:"
az ad app show --id "$APP_ID" \
  --query "{web:web.redirectUris,spa:spa.redirectUris,publicClient:publicClient.redirectUris}"
echo "Review every client first, then replace non-loopback HTTP entries with exact HTTPS URIs."
echo "Use 'az ad app update --id <id> --web-redirect-uris <complete-approved-list>' for web clients."
echo "No automatic change was made because replacing an incomplete URI list can break authentication."
