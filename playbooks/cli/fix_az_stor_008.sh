#!/bin/bash
# Rule: AZ-STOR-008 - Required Storage Customer-Managed Key Protection Missing
set -euo pipefail
RESOURCE_GROUP="${1:-}"; RESOURCE_NAME="${2:-}"; KEY_URI="${3:-}"
if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ] || [ -z "$KEY_URI" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name> <key-uri>"; exit 1
fi
echo "Customer-managed-key remediation requires a validated Key Vault key URI and operator review."
az storage account update --name "$RESOURCE_NAME" --resource-group "$RESOURCE_GROUP" --encryption-key-source Microsoft.Keyvault --encryption-key-vault "${KEY_URI%/*}" --encryption-key-name "${KEY_URI##*/}"
