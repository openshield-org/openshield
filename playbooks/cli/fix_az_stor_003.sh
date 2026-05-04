#!/bin/bash
# OpenShield Remediation Playbook
# Rule:     AZ-STOR-003 — Storage Account Has No Lifecycle Management Policy
# Usage:    ./fix_az_stor_003.sh <resource-group> <storage-account-name> [days-to-delete]
# Severity: MEDIUM
#
# What this script does:
#   1. Enables last access time tracking on the storage account (required
#      prerequisite for daysAfterLastAccessTimeGreaterThan policies).
#   2. Creates a lifecycle management policy with three tiers:
#      - Move to Cool tier after 30 days of no access
#      - Move to Archive tier after 90 days of no access
#      - Delete blobs after <days-to-delete> days (default 365)
#   3. The same delete rule applies to blob snapshots.
#
# Prerequisites:
#   - Azure CLI installed and logged in  (az login)
#   - Contributor or Storage Account Contributor role on the target account
#   - The storage account must use StorageV2 or BlobStorage kind for lifecycle
#     management. Classic and premium accounts are not supported.
#
# Example:
#   ./fix_az_stor_003.sh my-resource-group my-storage-account 365

set -euo pipefail

RESOURCE_GROUP="${1:-}"
STORAGE_ACCOUNT="${2:-}"
DAYS_TO_DELETE="${3:-365}"

# ── Argument validation ──────────────────────────────────────────────────────

if [ -z "$RESOURCE_GROUP" ] || [ -z "$STORAGE_ACCOUNT" ]; then
  echo "Usage: $0 <resource-group> <storage-account-name> [days-to-delete]"
  echo ""
  echo "Arguments:"
  echo "  resource-group        Name of the Azure resource group"
  echo "  storage-account-name  Name of the storage account to remediate"
  echo "  days-to-delete        Days before blobs are permanently deleted (default: 365)"
  echo ""
  echo "Example:"
  echo "  $0 my-resource-group my-storage-account 365"
  exit 1
fi

# ── Validate days-to-delete is a positive integer ────────────────────────────

if ! [[ "$DAYS_TO_DELETE" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: days-to-delete must be a positive integer (got: '$DAYS_TO_DELETE')"
  exit 1
fi

# ── Validate names contain only Azure-safe characters ───────────────────────
# Resource group: letters, numbers, hyphens, underscores, dots, parentheses
# Storage account: lowercase letters and numbers only (Azure naming constraint)

if ! [[ "$RESOURCE_GROUP" =~ ^[a-zA-Z0-9._()-]+$ ]]; then
  echo "ERROR: resource-group contains invalid characters: '$RESOURCE_GROUP'"
  exit 1
fi

if ! [[ "$STORAGE_ACCOUNT" =~ ^[a-z0-9]{3,24}$ ]]; then
  echo "ERROR: storage-account-name must be 3-24 lowercase letters and numbers only."
  exit 1
fi

# ── Validate DAYS_TO_DELETE range is sane ────────────────────────────────────
# Azure requires tier transition <= delete threshold. Archive at 90 < delete.

if [ "$DAYS_TO_DELETE" -lt 91 ]; then
  echo "ERROR: days-to-delete must be at least 91 (must exceed the Archive tier at 90 days)"
  exit 1
fi

# ── Secure temp file with guaranteed cleanup on exit or error ─────────────────

POLICY_FILE=$(mktemp)
chmod 600 "$POLICY_FILE"

cleanup() {
  rm -f "$POLICY_FILE"
}
trap cleanup EXIT

# ── Confirm before making changes ────────────────────────────────────────────

echo "============================================================"
echo "  OpenShield Remediation — AZ-STOR-003"
echo "============================================================"
echo ""
echo "  Storage account : $STORAGE_ACCOUNT"
echo "  Resource group  : $RESOURCE_GROUP"
echo "  Delete after    : $DAYS_TO_DELETE days"
echo ""
echo "  Steps:"
echo "    1. Enable last access time tracking (required prerequisite)"
echo "    2. Create lifecycle policy with three tiers:"
echo "       - Move to Cool tier  after 30 days of no access"
echo "       - Move to Archive    after 90 days of no access"
echo "       - Delete permanently after $DAYS_TO_DELETE days of no access"
echo ""
echo "  NOTE: This requires StorageV2 or BlobStorage account kind."
echo "  Premium and Classic accounts do not support lifecycle management."
echo ""
read -r -p "Proceed? [y/N] " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "Aborted. No changes were made."
  exit 0
fi

# ── Step 1: Enable last access time tracking ─────────────────────────────────
# REQUIRED before daysAfterLastAccessTimeGreaterThan can be used in a policy.
# Without this, the Azure API accepts the policy JSON but the tier transitions
# never fire — the account stays non-compliant silently.

echo ""
echo "[1/2] Enabling last access time tracking on: $STORAGE_ACCOUNT ..."

az storage account blob-service-properties update \
  --account-name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --enable-last-access-tracking true

echo "      Last access tracking enabled."

# ── Step 2: Write and apply the lifecycle policy ──────────────────────────────
# DAYS_TO_DELETE is validated as a positive integer >= 91 above.
# All variable expansions inside the heredoc are safe.

echo ""
echo "[2/2] Applying lifecycle management policy to: $STORAGE_ACCOUNT ..."

cat > "$POLICY_FILE" << EOF
{
  "rules": [
    {
      "name": "openshield-lifecycle-rule",
      "enabled": true,
      "type": "Lifecycle",
      "definition": {
        "filters": {
          "blobTypes": ["blockBlob"]
        },
        "actions": {
          "baseBlob": {
            "tierToCool": {
              "daysAfterLastAccessTimeGreaterThan": 30
            },
            "tierToArchive": {
              "daysAfterLastAccessTimeGreaterThan": 90
            },
            "delete": {
              "daysAfterLastAccessTimeGreaterThan": ${DAYS_TO_DELETE}
            }
          },
          "snapshot": {
            "delete": {
              "daysAfterCreationGreaterThan": ${DAYS_TO_DELETE}
            }
          }
        }
      }
    }
  ]
}
EOF

az storage account management-policy create \
  --account-name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --policy "@${POLICY_FILE}"

# Temp file removed automatically by trap on EXIT.

# ── Confirmation ─────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Remediation complete for: $STORAGE_ACCOUNT"
echo "============================================================"
echo ""
echo "  Applied:"
echo "    Last access time tracking : enabled"
echo "    Move to Cool    after  30 days of no access"
echo "    Move to Archive after  90 days of no access"
echo "    Delete          after $DAYS_TO_DELETE days of no access"
echo ""
echo "  To verify the policy was applied:"
echo "    az storage account management-policy show \\"
echo "      --account-name $STORAGE_ACCOUNT \\"
echo "      --resource-group $RESOURCE_GROUP"
echo ""
echo "  NOTE: Adjust tier thresholds and delete day to match your"
echo "  organisation's data retention and compliance policy."
echo "============================================================"
