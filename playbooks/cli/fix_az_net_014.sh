#!/bin/bash
set -euo pipefail

RESOURCE_GROUP=$1
VNET_NAME=$2
PEERING_NAME=$3

if [ -z "$RESOURCE_GROUP" ] || [ -z "$VNET_NAME" ] || [ -z "$PEERING_NAME" ]; then
  echo "Usage: $0 <resource-group> <vnet-name> <peering-name>"
  exit 1
fi

echo "Disabling gateway transit on peering: $PEERING_NAME"

az network vnet peering update \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$PEERING_NAME" \
  --set allowGatewayTransit=false useRemoteGateways=false

echo "Done. Gateway transit disabled on peering: $PEERING_NAME"
echo "Note: Verify that disabling gateway transit does not break any intended routing before applying to production."