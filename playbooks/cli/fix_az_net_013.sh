#!/bin/bash
# Playbook: fix_az_net_013.sh
# Rule: AZ-NET-013 - Azure Firewall not enabled on Virtual Network

set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <resource-group> <vnet-name> [location] [firewall-name]"
  echo ""
  echo "Deploys an Azure Firewall into the target virtual network so traffic"
  echo "can be inspected, filtered, and logged at the network perimeter."
  echo "Note: Azure Firewall is a billed resource - review pricing first."
  exit 1
fi

RESOURCE_GROUP="$1"
VNET_NAME="$2"
LOCATION="${3:-}"
FIREWALL_NAME="${4:-${VNET_NAME}-fw}"
PUBLIC_IP_NAME="${FIREWALL_NAME}-pip"

# Azure Firewall requires a dedicated subnet named exactly "AzureFirewallSubnet"
# with a minimum prefix of /26.
FIREWALL_SUBNET_NAME="AzureFirewallSubnet"
FIREWALL_SUBNET_PREFIX="${FIREWALL_SUBNET_PREFIX:-10.0.255.0/26}"

# Derive the VNet location if one was not supplied.
if [[ -z "$LOCATION" ]]; then
  echo "Resolving location for VNet '$VNET_NAME'..."
  LOCATION=$(az network vnet show \
    --resource-group "$RESOURCE_GROUP" \
    --name "$VNET_NAME" \
    --query "location" --output tsv)
fi

echo "Ensuring '$FIREWALL_SUBNET_NAME' exists in VNet '$VNET_NAME'..."
if ! az network vnet subnet show \
      --resource-group "$RESOURCE_GROUP" \
      --vnet-name "$VNET_NAME" \
      --name "$FIREWALL_SUBNET_NAME" >/dev/null 2>&1; then
  echo "  Creating subnet '$FIREWALL_SUBNET_NAME' ($FIREWALL_SUBNET_PREFIX)..."
  echo "  (Adjust FIREWALL_SUBNET_PREFIX to a free /26 range in your VNet.)"
  az network vnet subnet create \
    --resource-group "$RESOURCE_GROUP" \
    --vnet-name "$VNET_NAME" \
    --name "$FIREWALL_SUBNET_NAME" \
    --address-prefixes "$FIREWALL_SUBNET_PREFIX" \
    --output none
fi

echo "Creating Standard Static public IP '$PUBLIC_IP_NAME'..."
az network public-ip create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$PUBLIC_IP_NAME" \
  --location "$LOCATION" \
  --sku Standard \
  --allocation-method Static \
  --output none

echo "Creating Azure Firewall '$FIREWALL_NAME'..."
az network firewall create \
  --resource-group "$RESOURCE_GROUP" \
  --name "$FIREWALL_NAME" \
  --location "$LOCATION" \
  --output none

echo "Associating firewall with VNet '$VNET_NAME' and public IP..."
az network firewall ip-config create \
  --resource-group "$RESOURCE_GROUP" \
  --firewall-name "$FIREWALL_NAME" \
  --name "${FIREWALL_NAME}-ipconfig" \
  --vnet-name "$VNET_NAME" \
  --public-ip-address "$PUBLIC_IP_NAME" \
  --output none

echo "Done. Azure Firewall '$FIREWALL_NAME' deployed in VNet '$VNET_NAME'."
echo "Next steps:"
echo "  - Add firewall rules (network/application/NAT) to permit required traffic."
echo "  - Create a route table sending subnet traffic (0.0.0.0/0) to the firewall"
echo "    private IP, then associate it with the workload subnets."
echo "Verify with:"
echo "  az network firewall show --resource-group $RESOURCE_GROUP --name $FIREWALL_NAME --output table"
