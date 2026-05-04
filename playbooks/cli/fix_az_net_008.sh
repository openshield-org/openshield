#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-NET-008 — Load balancer with no backend pool configured
# Usage: ./fix_az_net_008.sh <resource-group> <lb-name>
# Severity: LOW

set -e

RESOURCE_GROUP=$1
LB_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$LB_NAME" ]; then
  echo "Usage: $0 <resource-group> <lb-name>"
  echo ""
  echo "Options:"
  echo "  1. Delete the load balancer if no longer needed:"
  echo "     az network lb delete --resource-group <rg> --name <lb-name>"
  echo ""
  echo "  2. Add a backend pool if the load balancer is still required:"
  echo "     az network lb address-pool create --resource-group <rg> --lb-name <lb-name> --name <pool-name>"
  exit 1
fi

echo "Deleting empty load balancer '$LB_NAME'..."

az network lb delete \
  --resource-group "$RESOURCE_GROUP" \
  --name "$LB_NAME"

echo "✅ Load balancer '$LB_NAME' deleted."
echo "⚠️  If this load balancer is still needed, create a backend pool instead of deleting."
