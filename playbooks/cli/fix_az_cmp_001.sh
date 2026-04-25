#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-CMP-001 — VM with Public IP and No Associated NSG on Network Interface
# Usage: ./fix_az_cmp_001.sh <resource-group> <nic-name> <nsg-name>
# Severity: HIGH
#
# This script associates an existing NSG with the vulnerable NIC.
# If the NSG does not yet exist, create it first:
#   az network nsg create --resource-group <rg> --name <nsg-name>

set -e

RESOURCE_GROUP=$1
NIC_NAME=$2
NSG_NAME=$3

if [ -z "$RESOURCE_GROUP" ] || [ -z "$NIC_NAME" ] || [ -z "$NSG_NAME" ]; then
  echo "Usage: $0 <resource-group> <nic-name> <nsg-name>"
  echo ""
  echo "To create a new NSG first:"
  echo "  az network nsg create --resource-group <rg> --name <nsg-name>"
  exit 1
fi

echo "Associating NSG '$NSG_NAME' with NIC '$NIC_NAME'..."

az network nic update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$NIC_NAME" \
  --network-security-group "$NSG_NAME"

echo "✅ Remediation complete for $NIC_NAME — NSG '$NSG_NAME' is now associated."
echo "⚠️  Review the NSG rules to ensure only necessary inbound traffic is permitted."
