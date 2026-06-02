#!/bin/bash
# Playbook: fix_az_idn_006.sh
# Rule: AZ-IDN-006 — Service principal client secret older than 90 days

set -euo pipefail

echo "========================================"
echo " AZ-IDN-006 Remediation Playbook"
echo " Rotate Stale Service Principal Client Secrets"
echo "========================================"
echo ""
echo "Client secrets older than 90 days or with no expiry must be rotated."
echo "The safest long-term fix is to migrate to managed identities or certificates."
echo ""

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <app_id> [new_end_date]"
  echo "  app_id      — Application (client) ID from the scanner finding"
  echo "  new_end_date — Optional expiry date in YYYY-MM-DD format (default: 90 days)"
  echo ""
  echo "Step 1 — List all application credentials"
  echo "  az ad app credential list --id <app-id> --output table"
  echo ""
  echo "Step 2 — Reset the credential with a 90-day expiry"
  echo "  az ad app credential reset --id <app-id> \\"
  echo "    --end-date \$(date -d '+90 days' +%Y-%m-%d)"
  echo ""
  echo "Step 3 — Update the consuming service with the new secret"
  echo "  Store the new secret in Azure Key Vault, not in config files."
  echo ""
  echo "Step 4 — Consider migrating to managed identity"
  echo "  az webapp identity assign --name <app-name> --resource-group <rg>"
  echo ""
  exit 0
fi

APP_ID="$1"
END_DATE="${2:-$(date -d '+90 days' +%Y-%m-%d 2>/dev/null || date -v+90d +%Y-%m-%d)}"

echo "Step 1 — Current credentials for app $APP_ID"
az ad app credential list --id "$APP_ID" --output table \
  || { echo "Could not list credentials. Run az login first."; exit 1; }

echo ""
echo "Step 2 — Resetting credential with expiry $END_DATE"
echo "WARNING: This will generate a new secret. Update all services using this app."
read -r -p "Continue? (y/N): " confirm
if [[ "${confirm,,}" != "y" ]]; then
  echo "Aborted."
  exit 0
fi

az ad app credential reset --id "$APP_ID" --end-date "$END_DATE"

echo ""
echo "New secret generated. Store it in Azure Key Vault immediately."
echo "Do not log or commit the secret value."
echo ""
echo "Remediation complete. Re-run the scanner after 24 hours to verify."
