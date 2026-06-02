#!/bin/bash
# OpenShield Remediation Playbook
# Rule:     AZ-STOR-004 — Storage Account Diagnostic Logging Disabled
# Usage:    ./fix_az_stor_004.sh <resource-group> <storage-account-name> <log-storage-account-id>
# Severity: MEDIUM
#
# What this script does:
#   Enables Azure Monitor diagnostic settings on the blob, queue, and table
#   service sub-resources of the specified storage account. Each service gets
#   a diagnostic setting named "openshield-storage-logging" with StorageRead,
#   StorageWrite, and StorageDelete enabled at a 90-day retention. Logs are
#   written to the destination storage account you supply.
#
# Prerequisites:
#   - Azure CLI installed and logged in  (az login)
#   - Contributor or Monitoring Contributor role on the target subscription
#   - A destination storage account for logs (pass its full resource ID)
#
# Example:
#   ./fix_az_stor_004.sh my-rg my-storage-account \
#     /subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/log-rg/providers/Microsoft.Storage/storageAccounts/logstore

set -euo pipefail

RESOURCE_GROUP="${1:-}"
STORAGE_ACCOUNT="${2:-}"
LOG_STORAGE_ACCOUNT_ID="${3:-}"

# ── Argument validation ──────────────────────────────────────────────────────

if [ -z "$RESOURCE_GROUP" ] || [ -z "$STORAGE_ACCOUNT" ] || [ -z "$LOG_STORAGE_ACCOUNT_ID" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name> <log-storage-account-id>"
  echo ""
  echo "Arguments:"
  echo "  resource-group          Resource group of the storage account to remediate"
  echo "  storage-account-name    Name of the storage account to remediate"
  echo "  log-storage-account-id  Full Azure resource ID of the destination log storage account"
  echo ""
  echo "Example:"
  echo "  $0 my-rg my-storage \\"
  echo "    /subscriptions/<sub-id>/resourceGroups/log-rg/providers/Microsoft.Storage/storageAccounts/logstore"
  exit 1
fi

# ── Validate names contain only Azure-safe characters ───────────────────────

if ! [[ "$RESOURCE_GROUP" =~ ^[a-zA-Z0-9._()-]+$ ]]; then
  echo "ERROR: resource-group contains invalid characters: '$RESOURCE_GROUP'"
  exit 1
fi

if ! [[ "$STORAGE_ACCOUNT" =~ ^[a-z0-9]{3,24}$ ]]; then
  echo "ERROR: storage-account-name must be 3-24 lowercase letters and numbers only."
  exit 1
fi

# ── Resolve subscription ID ──────────────────────────────────────────────────

SUBSCRIPTION_ID=$(az account show --query id -o tsv)
if [ -z "$SUBSCRIPTION_ID" ]; then
  echo "ERROR: Could not determine subscription ID. Run 'az login' first."
  exit 1
fi

# ── Build base resource ID ───────────────────────────────────────────────────

BASE_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Storage/storageAccounts/${STORAGE_ACCOUNT}"

BLOB_RESOURCE_ID="${BASE_ID}/blobServices/default"
QUEUE_RESOURCE_ID="${BASE_ID}/queueServices/default"
TABLE_RESOURCE_ID="${BASE_ID}/tableServices/default"

LOG_SETTING_NAME="openshield-storage-logging"

LOG_CATEGORIES='[
  {"category":"StorageRead","enabled":true,"retentionPolicy":{"days":90,"enabled":true}},
  {"category":"StorageWrite","enabled":true,"retentionPolicy":{"days":90,"enabled":true}},
  {"category":"StorageDelete","enabled":true,"retentionPolicy":{"days":90,"enabled":true}}
]'

# ── Confirm before making changes ────────────────────────────────────────────

echo "============================================================"
echo "  OpenShield Remediation — AZ-STOR-004"
echo "============================================================"
echo ""
echo "  Storage account  : $STORAGE_ACCOUNT"
echo "  Resource group   : $RESOURCE_GROUP"
echo "  Log destination  : $LOG_STORAGE_ACCOUNT_ID"
echo ""
echo "  Services to configure:"
echo "    - blobServices/default"
echo "    - queueServices/default"
echo "    - tableServices/default"
echo ""
echo "  Each service will have diagnostic setting '$LOG_SETTING_NAME' with:"
echo "    StorageRead, StorageWrite, StorageDelete (retention 90 days)"
echo ""
read -r -p "Proceed? [y/N] " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "Aborted. No changes were made."
  exit 0
fi

# ── Enable diagnostic settings on all three services ────────────────────────

echo ""
echo "[1/3] Enabling diagnostic logging on blob service ..."
az monitor diagnostic-settings create \
  --resource  "$BLOB_RESOURCE_ID" \
  --name      "$LOG_SETTING_NAME" \
  --storage-account "$LOG_STORAGE_ACCOUNT_ID" \
  --logs      "$LOG_CATEGORIES"
echo "      Done."

echo ""
echo "[2/3] Enabling diagnostic logging on queue service ..."
az monitor diagnostic-settings create \
  --resource  "$QUEUE_RESOURCE_ID" \
  --name      "$LOG_SETTING_NAME" \
  --storage-account "$LOG_STORAGE_ACCOUNT_ID" \
  --logs      "$LOG_CATEGORIES"
echo "      Done."

echo ""
echo "[3/3] Enabling diagnostic logging on table service ..."
az monitor diagnostic-settings create \
  --resource  "$TABLE_RESOURCE_ID" \
  --name      "$LOG_SETTING_NAME" \
  --storage-account "$LOG_STORAGE_ACCOUNT_ID" \
  --logs      "$LOG_CATEGORIES"
echo "      Done."

# ── Confirmation ─────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Remediation complete for: $STORAGE_ACCOUNT"
echo "============================================================"
echo ""
echo "  Diagnostic setting '$LOG_SETTING_NAME' created on:"
echo "    blobServices/default   — StorageRead, StorageWrite, StorageDelete (90-day retention)"
echo "    queueServices/default  — StorageRead, StorageWrite, StorageDelete (90-day retention)"
echo "    tableServices/default  — StorageRead, StorageWrite, StorageDelete (90-day retention)"
echo ""
echo "  To verify:"
echo "    az monitor diagnostic-settings list --resource $BLOB_RESOURCE_ID"
echo "    az monitor diagnostic-settings list --resource $QUEUE_RESOURCE_ID"
echo "    az monitor diagnostic-settings list --resource $TABLE_RESOURCE_ID"
echo "============================================================"
