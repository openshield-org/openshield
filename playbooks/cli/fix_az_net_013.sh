#!/bin/bash
set -euo pipefail

RESOURCE_GROUP=$1
VNET_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$VNET_NAME" ]; then
  echo "Usage: $0 <resource-group> <vnet-name>"
  exit 1
fi

echo "Deploying Azure Firewall for VNet: $VNET_NAME in resource group: $RESOURCE_GROUP..."

az network vnet subnet create \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name AzureFirewallSubnet \
  --address-prefixes 10.0.1.0/26

az network public-ip create \
  --resource-group "$RESOURCE_GROUP" \
  --name "${VNET_NAME}-fw-pip" \
  --sku Standard \
  --allocation-method Static

az network firewall create \
  --resource-group "$RESOURCE_GROUP" \
  --name "${VNET_NAME}-firewall" \
  --sku-name AZFW_VNet \
  --sku-tier Standard

echo "Azure Firewall deployed for VNet: $VNET_NAME"
echo "Note: Configure network and application rules to control traffic before routing through the firewall."