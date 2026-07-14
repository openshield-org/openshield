#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-AKS-001 - AKS private cluster not enabled
# Usage: ./fix_az_aks_001.sh <resource-group> <cluster-name>
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
echo "WARNING: Enabling a private API endpoint changes cluster connectivity and DNS requirements."
echo "Confirm that administrators and automation have private network access before continuing."
read -r -p "Type APPLY to enable private-cluster mode on '$CLUSTER_NAME': " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az aks update --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" --enable-private-cluster
az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" \
  --query "apiServerAccessProfile.enablePrivateCluster" --output tsv
