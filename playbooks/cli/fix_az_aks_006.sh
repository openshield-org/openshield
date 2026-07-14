#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-AKS-006 - AKS node OS automatic upgrades disabled
# Usage: ./fix_az_aks_006.sh <resource-group> <cluster-name>
# Severity: HIGH

set -euo pipefail

RESOURCE_GROUP=${1:-}
CLUSTER_NAME=${2:-}
if [ -z "$RESOURCE_GROUP" ] || [ -z "$CLUSTER_NAME" ]; then
  echo "Usage: $0 <resource-group> <cluster-name>"
  exit 1
fi

az account show --output none
az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" --output none
echo "WARNING: SecurityPatch updates can reimage nodes when required."
echo "Configure and validate an AKS planned-maintenance window for production clusters."
read -r -p "Type APPLY to enable SecurityPatch on '$CLUSTER_NAME': " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az aks update --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" \
  --node-os-upgrade-channel SecurityPatch
az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" \
  --query "autoUpgradeProfile.nodeOsUpgradeChannel" --output tsv
