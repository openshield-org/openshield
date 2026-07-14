#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-AKS-004 - AKS Workload Identity not fully enabled
# Usage: ./fix_az_aks_004.sh <resource-group> <cluster-name>
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
echo "This enables the OIDC issuer and Workload Identity platform features."
echo "Each workload still requires a federated identity credential and service-account annotation."
read -r -p "Type APPLY to continue for '$CLUSTER_NAME': " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }

az aks update --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" \
  --enable-oidc-issuer --enable-workload-identity
az aks show --resource-group "$RESOURCE_GROUP" --name "$CLUSTER_NAME" \
  --query "{oidc:oidcIssuerProfile.enabled,workloadIdentity:securityProfile.workloadIdentity.enabled}"
