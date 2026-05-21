#!/bin/bash
# AZ-DB-004: Enable auditing on an Azure SQL Server
# Usage: ./fix_az_db_004.sh <resource-group> <server-name> <storage-account-name>

RESOURCE_GROUP=$1
SERVER_NAME=$2
STORAGE_ACCOUNT=$3

if [ -z "$RESOURCE_GROUP" ] || [ -z "$SERVER_NAME" ] || [ -z "$STORAGE_ACCOUNT" ]; then
  echo "Usage: $0 <resource-group> <server-name> <storage-account-name>"
  exit 1
fi

echo "Enabling auditing on SQL Server: $SERVER_NAME..."

az sql server audit-policy update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$SERVER_NAME" \
  --state Enabled \
  --storage-account "$STORAGE_ACCOUNT"

echo "✅ Auditing enabled for SQL Server: $SERVER_NAME"
echo "Logs will be sent to storage account: $STORAGE_ACCOUNT"