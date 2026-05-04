#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-NET-006 — Public IP address unassociated with any resource
# Usage: ./fix_az_net_006.sh <resource-group> <public-ip-name>
# Severity: LOW

set -e

RESOURCE_GROUP=$1
PUBLIC_IP_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$PUBLIC_IP_NAME" ]; then
  echo "Usage: $0 <resource-group> <public-ip-name>"
  exit 1
fi

echo "Deleting unassociated public IP '$PUBLIC_IP_NAME'..."

az network public-ip delete \
  --resource-group "$RESOURCE_GROUP" \
  --name "$PUBLIC_IP_NAME"

echo "✅ Public IP '$PUBLIC_IP_NAME' deleted successfully."
echo "⚠️  If this IP was reserved for future use, reassign it to a resource instead of deleting."
