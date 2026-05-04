#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-NET-004 — NSG with no rules configured
# Usage: ./fix_az_net_004.sh <resource-group> <nsg-name>
# Severity: MEDIUM

set -e

RESOURCE_GROUP=$1
NSG_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$NSG_NAME" ]; then
  echo "Usage: $0 <resource-group> <nsg-name>"
  exit 1
fi

echo "Adding default deny-all inbound rule to NSG '$NSG_NAME'..."

az network nsg rule create \
  --resource-group "$RESOURCE_GROUP" \
  --nsg-name "$NSG_NAME" \
  --name "DenyAllInbound" \
  --priority 4096 \
  --direction Inbound \
  --access Deny \
  --protocol "*" \
  --source-address-prefixes "*" \
  --destination-address-prefixes "*" \
  --destination-port-ranges "*"

echo "✅ Default deny-all inbound rule added to $NSG_NAME"
echo "⚠️  Now add specific allow rules for your workload traffic."
