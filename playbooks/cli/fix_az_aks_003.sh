#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-AKS-003 - AKS cluster not using managed identity
# Usage: ./fix_az_aks_003.sh <resource-group> <cluster-name>
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
echo "WARNING: Migration changes the cluster control-plane identity."
echo "Review dependent role assignments and allow time for permission propagation."
read -r -p "Type APPLY to enable managed identity on '$CLUSTER_NAME': " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az aks update --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" --enable-managed-identity
az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" \
  --query "identity.type" --output tsv
