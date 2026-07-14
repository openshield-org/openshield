#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-AKS-005 - AKS Azure Policy add-on not enabled
# Usage: ./fix_az_aks_005.sh <resource-group> <cluster-name>
# Severity: MEDIUM

set -euo pipefail

RESOURCE_GROUP=${1:-}
CLUSTER_NAME=${2:-}
if [ -z "$RESOURCE_GROUP" ] || [ -z "$CLUSTER_NAME" ]; then
  echo "Usage: $0 <resource-group> <cluster-name>"
  exit 1
fi

az account show --output none
az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" --output none
echo "Enable the add-on first, then roll out policy initiatives in audit mode before deny mode."
read -r -p "Type APPLY to enable Azure Policy on '$CLUSTER_NAME': " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az aks enable-addons --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" --addons azure-policy
az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" \
  --query "addonProfiles.azurepolicy.enabled" --output tsv
