#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-NET-002 — NSG Allows Unrestricted Inbound RDP from Any Source
# Usage: ./fix_az_net_002.sh <resource-group> <nsg-name> [rule-name]
# Severity: HIGH
#
# Pass the optional rule-name if the offending rule is known (shown in finding metadata).

set -e

RESOURCE_GROUP=$1
RESOURCE_NAME=$2
RULE_NAME=${3:-""}

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <nsg-name> [rule-name]"
  exit 1
fi

if [ -n "$RULE_NAME" ]; then
  echo "Deleting NSG rule '$RULE_NAME' from $RESOURCE_NAME"
  az network nsg rule delete \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$RESOURCE_NAME" \
    --name "$RULE_NAME"
else
  echo "Searching for inbound RDP rules in $RESOURCE_NAME..."
  RULES=$(az network nsg rule list \
    --resource-group "$RESOURCE_GROUP" \
    --nsg-name "$RESOURCE_NAME" \
    --query "[?direction=='Inbound' && access=='Allow' && destinationPortRange=='3389' && (sourceAddressPrefix=='*' || sourceAddressPrefix=='0.0.0.0/0' || sourceAddressPrefix=='Internet')].name" \
    --output tsv)

  if [ -z "$RULES" ]; then
    echo "No matching open RDP rule found — manual review recommended."
    exit 0
  fi

  for RULE in $RULES; do
    echo "Deleting rule: $RULE"
    az network nsg rule delete \
      --resource-group "$RESOURCE_GROUP" \
      --nsg-name "$RESOURCE_NAME" \
      --name "$RULE"
  done
fi

echo "✅ Remediation complete for $RESOURCE_NAME — unrestricted RDP access removed."
