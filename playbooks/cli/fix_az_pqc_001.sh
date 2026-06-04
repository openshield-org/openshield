#!/bin/bash
set -euo pipefail

# Playbook: fix_az_pqc_001.sh
# Rule: AZ-PQC-001 - TLS using classical key exchange algorithm

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <resource-group> <app-name>"
  exit 1
fi

RESOURCE_GROUP="$1"
APP_NAME="$2"

echo "Enforcing TLS 1.3 minimum on App Service: $APP_NAME"
az webapp config set \
  --resource-group "$RESOURCE_GROUP" \
  --name "$APP_NAME" \
  --min-tls-version 1.3 \
  --output none

echo "Done. Verify with:"
echo "  az webapp config show --resource-group $RESOURCE_GROUP --name $APP_NAME --query minTlsVersion"
