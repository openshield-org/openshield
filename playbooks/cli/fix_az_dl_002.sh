#!/bin/bash
set -euo pipefail

RESOURCE_GROUP=${1:-}
PORT_NAME=${2:-}
LINK_NAME=${3:-}

if [ -z "$RESOURCE_GROUP" ] || [ -z "$PORT_NAME" ] || [ -z "$LINK_NAME" ]; then
  echo "Usage: $0 <resource-group> <port-name> <link-name>"
  exit 1
fi

echo "Confirm the connected router supports GcmAesXpn256 and arrange a maintenance window."
echo "Key references remain unchanged. This script never reads or prints CAK or CKN secret values."
read -r -p "Type APPLY to change the configured cipher: " CONFIRMATION
if [ "$CONFIRMATION" != "APPLY" ]; then
  echo "No change made."
  exit 0
fi

az network express-route port link update \
  --resource-group "$RESOURCE_GROUP" \
  --port-name "$PORT_NAME" \
  --name "$LINK_NAME" \
  --macsec-cipher GcmAesXpn256

echo "Cipher update submitted. Verify link counters and traffic before closing the maintenance window."
