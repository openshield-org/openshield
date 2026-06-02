#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-KV-003 - Key Vault Without Diagnostic Logging Enabled
# Usage: ./fix_az_kv_003.sh <vault-name> <resource-group> <workspace-id>
# Severity: MEDIUM

set -euo pipefail

VAULT_NAME="${1:-}"
RESOURCE_GROUP="${2:-}"
WORKSPACE_ID="${3:-}"

if [[ -z "$VAULT_NAME" || -z "$RESOURCE_GROUP" || -z "$WORKSPACE_ID" ]]; then
    echo "Usage: $0 <vault-name> <resource-group> <workspace-id>"
    exit 1
fi

echo "Fetching Key Vault resource ID..."

VAULT_ID=$(az keyvault show \
    --name "$VAULT_NAME" \
    --resource-group "$RESOURCE_GROUP" \
    --query id \
    -o tsv)

if [[ -z "$VAULT_ID" ]]; then
    echo "Failed to retrieve Key Vault resource ID."
    exit 1
fi

echo "Enabling diagnostic logging for Key Vault: $VAULT_NAME"

az monitor diagnostic-settings create \
    --name "OpenShieldDiagnostics" \
    --resource "$VAULT_ID" \
    --workspace "$WORKSPACE_ID" \
    --logs '[{"category":"AuditEvent","enabled":true}]'

echo "Diagnostic logging enabled successfully for Key Vault: $VAULT_NAME"
echo "Verify logs are flowing into the configured Log Analytics workspace."