#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-NET-010 — Subnet with no network security group attached
# Usage: ./fix_az_net_010.sh <resource-group> <vnet-name> <subnet-name> <nsg-name>
# Severity: HIGH

set -e

RESOURCE_GROUP=$1
VNET_NAME=$2
SUBNET_NAME=$3
NSG_NAME=$4

if [ -z "$RESOURCE_GROUP" ] || [ -z "$VNET_NAME" ] || [ -z "$SUBNET_NAME" ] || [ -z "$NSG_NAME" ]; then
  echo "Usage: $0 <resource-group> <vnet-name> <subnet-name> <nsg-name>"
  echo ""
  echo "To create a new NSG first:"
  echo "  az network nsg create --resource-group <rg> --name <nsg-name>"
  exit 1
fi

echo "Attaching NSG '$NSG_NAME' to subnet '$SUBNET_NAME' in VNet '$VNET_NAME'..."

az network vnet subnet update \
  --resource-group "$RESOURCE_GROUP" \
  --vnet-name "$VNET_NAME" \
  --name "$SUBNET_NAME" \
  --network-security-group "$NSG_NAME"

echo "✅ NSG '$NSG_NAME' attached to subnet '$SUBNET_NAME'."
echo "⚠️  Review NSG rules to ensure only required traffic is permitted."
