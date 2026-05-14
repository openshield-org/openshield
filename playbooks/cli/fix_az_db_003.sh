#!/bin/bash
# Playbook: fix_az_db_003.sh
# Rule: AZ-DB-003 — PostgreSQL Flexible Server SSL enforcement disabled

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <subscription_id>"
  exit 1
fi

SUBSCRIPTION_ID="$1"

echo "Setting subscription..."
az account set --subscription "$SUBSCRIPTION_ID"

echo "Fetching PostgreSQL Flexible Servers..."
SERVERS=$(az postgres flexible-server list   --subscription "$SUBSCRIPTION_ID"   --query "[].{name:name, rg:resourceGroup}"   --output tsv)

if [[ -z "$SERVERS" ]]; then
  echo "No PostgreSQL Flexible Servers found."
  exit 0
fi

while IFS=$'\t' read -r SERVER_NAME RESOURCE_GROUP; do
  echo "Checking $SERVER_NAME in $RESOURCE_GROUP..."
  SSL_VALUE=$(az postgres flexible-server parameter show     --resource-group "$RESOURCE_GROUP"     --server-name "$SERVER_NAME"     --name require_secure_transport     --query "value" --output tsv 2>/dev/null || echo "on")

  if [[ "${SSL_VALUE,,}" == "off" ]]; then
    echo "  [FIX] Enabling SSL on $SERVER_NAME..."
    az postgres flexible-server parameter set       --resource-group "$RESOURCE_GROUP"       --server-name "$SERVER_NAME"       --name require_secure_transport       --value ON       --output none
    echo "        Done."
  else
    echo "  [SKIP] $SERVER_NAME — SSL already enabled"
  fi
done <<< "$SERVERS"

echo "Done! Verify with:"
echo "  az postgres flexible-server parameter show --name require_secure_transport --server-name <name> --resource-group <rg>"
