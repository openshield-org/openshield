#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-DB-002 — Azure SQL Server Has No Auditing Configured
# Usage: ./fix_az_db_002.sh <resource-group> <server-name> <storage-account-name>
# Severity: MEDIUM

set -e

RESOURCE_GROUP=$1
RESOURCE_NAME=$2
STORAGE_ACCOUNT=$3

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ] || [ -z "$STORAGE_ACCOUNT" ]; then
  echo "Usage: $0 <resource-group> <server-name> <storage-account-name>"
  exit 1
fi

echo "Enabling SQL server auditing on: $RESOURCE_NAME"
echo "Audit logs will be written to storage account: $STORAGE_ACCOUNT"

# Get the storage account endpoint
STORAGE_ENDPOINT=$(az storage account show \
  --name "$STORAGE_ACCOUNT" \
  --resource-group "$RESOURCE_GROUP" \
  --query primaryEndpoints.blob \
  --output tsv)

az sql server audit-policy update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$RESOURCE_NAME" \
  --state Enabled \
  --blob-storage-target-state Enabled \
  --storage-account "$STORAGE_ACCOUNT" \
  --retention-days 90

echo "✅ Remediation complete for $RESOURCE_NAME — SQL auditing enabled with 90-day retention."
