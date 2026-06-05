#!/bin/bash
set -euo pipefail

# Playbook: fix_az_pqc_003.sh
# Rule: AZ-PQC-003 - Key Vault certificate using non-quantum-safe algorithm

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <resource-group> <vault-name> <cert-name>"
  exit 1
fi

RESOURCE_GROUP="$1"
VAULT_NAME="$2"
CERT_NAME="$3"

echo "Listing current certificate properties for: $CERT_NAME in vault: $VAULT_NAME"
az keyvault certificate show \
  --vault-name "$VAULT_NAME" \
  --name "$CERT_NAME" \
  --output table

echo ""
echo "Next steps:"
echo "  1. Identify the CA issuing this certificate."
echo "  2. Check if the CA supports post-quantum safe signature algorithms."
echo "  3. Document this certificate in your Cryptographic Bill of Materials."
echo "  4. Plan certificate renewal with a post-quantum safe algorithm."
echo "  5. Update all services using this certificate before expiry."
echo ""
echo "Verify existing certificates with:"
echo "  az keyvault certificate list --vault-name $VAULT_NAME --output table"
