#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-AKS-002 - AKS local accounts enabled
# Usage: ./fix_az_aks_002.sh <resource-group> <cluster-name>
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
echo "WARNING: Existing local kubeconfig credentials will stop working."
echo "Verify Microsoft Entra administrator access before continuing."
read -r -p "Type APPLY to disable local accounts on '$CLUSTER_NAME': " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az aks update --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" --disable-local-accounts
az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" \
  --query "disableLocalAccounts" --output tsv
