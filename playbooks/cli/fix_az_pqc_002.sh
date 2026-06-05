#!/bin/bash
set -euo pipefail

# Playbook: fix_az_pqc_002.sh
# Rule: AZ-PQC-002 - Key Vault key using non-quantum-safe algorithm

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <resource-group> <vault-name> <key-name>"
  exit 1
fi

RESOURCE_GROUP="$1"
VAULT_NAME="$2"
KEY_NAME="$3"

echo "Listing current key properties for: $KEY_NAME in vault: $VAULT_NAME"
az keyvault key show \
  --vault-name "$VAULT_NAME" \
  --name "$KEY_NAME" \
  --output table

echo ""
echo "Next steps:"
echo "  1. Review all workloads using this key and plan migration."
echo "  2. Generate a new key using a post-quantum safe algorithm when supported."
echo "  3. Document this key in your Cryptographic Bill of Materials (CBOM)."
echo "  4. Update all dependent services to use the new key."
echo "  5. Disable and schedule deletion of the old key after migration."
echo ""
echo "Verify existing keys with:"
echo "  az keyvault key list --vault-name $VAULT_NAME --output table"
