#!/bin/bash
set -euo pipefail

# Fix AZ-NET-012: Enable NSG Flow Logs
# Usage: ./fix_az_net_012.sh <resource_group> <nsg_name> <storage_account_id>

RESOURCE_GROUP=$1
NSG_NAME=$2
STORAGE_ACCOUNT_ID=$3

if [ -z "$RESOURCE_GROUP" ] || [ -z "$NSG_NAME" ] || [ -z "$STORAGE_ACCOUNT_ID" ]; then
    echo "ERROR: Missing required arguments"
    echo "Usage: $0 <resource_group> <nsg_name> <storage_account_id>"
    echo "Example: $0 my-rg my-nsg /subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Storage/storageAccounts/mystorage"
    exit 1
fi

echo "Enabling flow logs for NSG: $NSG_NAME"

az network watcher flow-log create \
    --nsg "$NSG_NAME" \
    --enabled true \
    --storage-account "$STORAGE_ACCOUNT_ID" \
    --resource-group "$RESOURCE_GROUP" \
    --name "${NSG_NAME}-flowlogs"

if [ $? -eq 0 ]; then
    echo "SUCCESS: Flow logs enabled successfully for $NSG_NAME"
else
    echo "FAILED: Failed to enable flow logs for $NSG_NAME"
    exit 1
fi