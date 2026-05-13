#!/bin/bash
# Playbook: fix_az_net_011.sh
# Rule: AZ-NET-011 — Network Watcher not enabled in all regions

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <subscription_id>"
  exit 1
fi

SUBSCRIPTION_ID="$1"

echo "Setting subscription..."
az account set --subscription "$SUBSCRIPTION_ID"

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
    RESOURCE_GROUP="NetworkWatcherRG-${REGION}"
    echo "  [FIX]  $REGION — creating resource group $RESOURCE_GROUP..."
    az group create --name "$RESOURCE_GROUP" --location "$REGION" --output none
    echo "  [FIX]  $REGION — enabling Network Watcher..."
    az network watcher configure \
      --resource-group "$RESOURCE_GROUP" \
      --locations "$REGION" \
      --enabled true \
      --subscription "$SUBSCRIPTION_ID" \
      --output none
    echo "         Done."
  fi
done <<< "$RESOURCE_REGIONS"

echo "Done! Verify with:"
echo "  az network watcher list --subscription $SUBSCRIPTION_ID --output table"
