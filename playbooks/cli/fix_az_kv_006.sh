#!/bin/bash
set -euo pipefail
# AZ-KV-006: Switch an Azure Key Vault from access policies to Azure RBAC authorization
# Usage: ./fix_az_kv_006.sh <resource-group> <vault-name>
RESOURCE_GROUP="${1:-}"
VAULT_NAME="${2:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$VAULT_NAME" ]; then
  echo "Usage: $0 <resource-group> <vault-name>"
  exit 1
fi
echo "WARNING: switching Key Vault '$VAULT_NAME' to RBAC authorization stops enforcing"
echo "its existing access policies. Assign equivalent RBAC roles BEFORE proceeding,"
echo "or callers relying on those access policies will lose access, e.g.:"
echo "  az role assignment create --role \"Key Vault Secrets User\" \\"
echo "    --assignee <principal-id> --scope <vault-resource-id>"
echo "Enabling RBAC authorization on Key Vault: $VAULT_NAME..."
az keyvault update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VAULT_NAME" \
  --enable-rbac-authorization true
echo "RBAC authorization enabled for Key Vault: $VAULT_NAME"
