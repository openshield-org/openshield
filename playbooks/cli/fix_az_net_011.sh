#!/bin/bash
# Playbook: fix_az_net_011.sh
# Rule: AZ-NET-011 — Network Watcher not enabled in all regions

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <subscription_id>"
  exit 1
fi

SUBSCRIPTION_ID="$1"
RESOURCE_GROUP="NetworkWatcherRG"

echo "Setting subscription..."
az account set --subscription "$SUBSCRIPTION_ID"

echo "Ensuring resource group exists..."
az group create --name "$RESOURCE_GROUP" --location eastus --output none 2>/dev/null || true

echo "Fetching regions with resources..."
RESOURCE_REGIONS=$(az resource list --subscription "$SUBSCRIPTION_ID" \
  --query "[].location" --output tsv | sort -u | tr -d ' ')

echo "Fetching regions with Network Watcher..."
WATCHED_REGIONS=$(az network watcher list --subscription "$SUBSCRIPTION_ID" \
  --query "[].location" --output tsv 2>/dev/null | sort -u | tr -d ' ' || echo "")

echo "Enabling Network Watcher in unmonitored regions..."
while IFS= read -r REGION; do
  if echo "$WATCHED_REGIONS" | grep -qx "$REGION"; then
    echo "  [SKIP] $REGION — already enabled"
  else
    echo "  [FIX]  $REGION — enabling..."
    az network watcher configure \
      --resource-group "$RESOURCE_GROUP" \
      --locations "$REGION" \
      --enabled true \
      --subscription "$SUBSCRIPTION_ID" \
      --output none
  fi
done <<< "$RESOURCE_REGIONS"

echo "Done! Verify with:"
echo "  az network watcher list --subscription $SUBSCRIPTION_ID --output table"
