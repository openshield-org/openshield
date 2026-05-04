#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-NET-005 — Virtual network with no DDoS protection enabled
# Usage: ./fix_az_net_005.sh <resource-group> <vnet-name> <ddos-plan-name>
# Severity: MEDIUM

set -e

RESOURCE_GROUP=$1
VNET_NAME=$2
DDOS_PLAN_NAME=$3

if [ -z "$RESOURCE_GROUP" ] || [ -z "$VNET_NAME" ] || [ -z "$DDOS_PLAN_NAME" ]; then
  echo "Usage: $0 <resource-group> <vnet-name> <ddos-plan-name>"
  echo ""
  echo "To create a new DDoS protection plan first:"
  echo "  az network ddos-protection create --resource-group <rg> --name <plan-name>"
  exit 1
fi

echo "Enabling DDoS protection on VNet '$VNET_NAME'..."

az network vnet update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VNET_NAME" \
  --ddos-protection true \
  --ddos-protection-plan "$DDOS_PLAN_NAME"

echo "✅ DDoS Protection Standard enabled on $VNET_NAME"
echo "⚠️  DDoS Protection Standard incurs additional cost — review Azure pricing."
