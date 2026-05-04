#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-NET-003 — NSG allows unrestricted inbound on port 443
# Usage: ./fix_az_net_003.sh <resource-group> <nsg-name> <rule-name> <allowed-ip-range>
# Severity: MEDIUM

set -e

RESOURCE_GROUP=$1
NSG_NAME=$2
RULE_NAME=$3
ALLOWED_IP=$4

if [ -z "$RESOURCE_GROUP" ] || [ -z "$NSG_NAME" ] || [ -z "$RULE_NAME" ] || [ -z "$ALLOWED_IP" ]; then
  echo "Usage: $0 <resource-group> <nsg-name> <rule-name> <allowed-ip-range>"
  echo ""
  echo "Example:"
  echo "  $0 my-rg my-nsg allow-https 203.0.113.0/24"
  exit 1
fi

echo "Restricting port 443 inbound rule '$RULE_NAME' in NSG '$NSG_NAME'..."

az network nsg rule update \
  --resource-group "$RESOURCE_GROUP" \
  --nsg-name "$NSG_NAME" \
  --name "$RULE_NAME" \
  --source-address-prefixes "$ALLOWED_IP"

echo "✅ Remediation complete — port 443 now restricted to $ALLOWED_IP"
echo "⚠️  Verify your application still functions correctly after this change."
