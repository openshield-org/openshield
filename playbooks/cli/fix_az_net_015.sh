#!/bin/bash
set -euo pipefail

RESOURCE_GROUP=$1
ZONE_NAME=$2
VNET_ID=$3

if [ -z "$RESOURCE_GROUP" ] || [ -z "$ZONE_NAME" ] || [ -z "$VNET_ID" ]; then
  echo "Usage: $0 <resource-group> <zone-name> <vnet-id>"
  exit 1
fi

echo "Creating private DNS zone: $ZONE_NAME"

az network private-dns zone create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$ZONE_NAME"

az network private-dns link vnet create \
  --resource-group "$RESOURCE_GROUP" \
  --zone-name "$ZONE_NAME" \
  --name "${ZONE_NAME}-link" \
  --virtual-network "$VNET_ID" \
  --registration-enabled false

echo "Done. Private DNS zone created and linked to VNet."
echo "Note: Migrate records from the public zone to the private zone before deleting the public zone."