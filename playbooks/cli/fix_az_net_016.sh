#!/usr/bin/env bash
# Review and disable IP forwarding on an Azure network interface.
set -euo pipefail

RESOURCE_GROUP="${1:-}"
NIC_NAME="${2:-}"

if [[ -z "$RESOURCE_GROUP" || -z "$NIC_NAME" ]]; then
  echo "Usage: $0 <resource-group> <network-interface-name>"
  exit 1
fi

echo "Confirm that $NIC_NAME is not an approved network virtual appliance before continuing."
read -r -p "Disable IP forwarding? [y/N] " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "No change made."
  exit 0
fi

az network nic update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$NIC_NAME" \
  --ip-forwarding false

echo "IP forwarding disabled on $NIC_NAME."
