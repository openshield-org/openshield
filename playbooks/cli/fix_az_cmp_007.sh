#!/usr/bin/env bash
# fix_az_cmp_007.sh
# Enable Microsoft Defender for Cloud Just-In-Time (JIT) VM access so a VM's
# management ports (SSH 22 / RDP 3389) are only opened on approved, time-boxed
# requests instead of standing open to the internet.
# Usage: ./fix_az_cmp_007.sh <resource-group> <vm-name> <location>
# Requires: Microsoft Defender for Servers enabled on the subscription.

set -euo pipefail

RESOURCE_GROUP="${1:-}"
VM_NAME="${2:-}"
LOCATION="${3:-}"

if [[ -z "$RESOURCE_GROUP" || -z "$VM_NAME" || -z "$LOCATION" ]]; then
  echo "Usage: $0 <resource-group> <vm-name> <location>"
  exit 1
fi

SUBSCRIPTION_ID="$(az account show --query id -o tsv)"
VM_ID="/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Compute/virtualMachines/${VM_NAME}"

echo "Enabling JIT access for $VM_NAME (ports 22, 3389) in $LOCATION..."

az rest --method PUT \
  --url "https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${RESOURCE_GROUP}/providers/Microsoft.Security/locations/${LOCATION}/jitNetworkAccessPolicies/default?api-version=2020-01-01" \
  --body "$(cat <<JSON
{
  "kind": "Basic",
  "properties": {
    "virtualMachines": [
      {
        "id": "${VM_ID}",
        "ports": [
          {"number": 22, "protocol": "*", "allowedSourceAddressPrefix": "*", "maxRequestAccessDuration": "PT3H"},
          {"number": 3389, "protocol": "*", "allowedSourceAddressPrefix": "*", "maxRequestAccessDuration": "PT3H"}
        ]
      }
    ]
  }
}
JSON
)"

echo "Done. JIT policy 'default' configured for $VM_NAME. Management ports now require an approved, time-boxed request."
