#!/bin/bash
set -euo pipefail
# AZ-DB-004: Remove the 'Allow all Azure services' firewall rule from an Azure SQL Server
# Usage: ./fix_az_db_004.sh <resource-group> <server-name>
RESOURCE_GROUP=$1
SERVER_NAME=$2
if [ -z "$RESOURCE_GROUP" ] || [ -z "$SERVER_NAME" ]; then
  echo "Usage: $0 <resource-group> <server-name>"
  exit 1
fi
echo "Removing 'AllowAllWindowsAzureIps' firewall rule from SQL Server: $SERVER_NAME..."
az sql server firewall-rule delete \
  --resource-group "$RESOURCE_GROUP" \
  --server "$SERVER_NAME" \
  --name "AllowAllWindowsAzureIps"
echo "Done. 'Allow access to Azure services' has been disabled for: $SERVER_NAME"
echo "Note: Add explicit firewall rules for trusted IP ranges if needed."