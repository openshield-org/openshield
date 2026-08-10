#!/bin/bash
set -euo pipefail

RESOURCE_GROUP=${1:-}
PORT_NAME=${2:-}
LINK_NAME=${3:-}
CAK_SECRET_ID=${4:-}
CKN_SECRET_ID=${5:-}

if [ -z "$RESOURCE_GROUP" ] || [ -z "$PORT_NAME" ] || [ -z "$LINK_NAME" ] || [ -z "$CAK_SECRET_ID" ] || [ -z "$CKN_SECRET_ID" ]; then
  echo "Usage: $0 <resource-group> <port-name> <link-name> <cak-key-vault-secret-id> <ckn-key-vault-secret-id>"
  exit 1
fi

echo "Review the ExpressRoute Direct peer configuration before continuing."
echo "This change can interrupt connectivity if both ends are not updated in the same maintenance window."
read -r -p "Type APPLY to enable XPN MACsec: " CONFIRMATION
if [ "$CONFIRMATION" != "APPLY" ]; then
  echo "No change made."
  exit 0
fi

az network express-route port link update \
  --resource-group "$RESOURCE_GROUP" \
  --port-name "$PORT_NAME" \
  --name "$LINK_NAME" \
  --macsec-cipher GcmAesXpn256 \
  --macsec-cak-secret-identifier "$CAK_SECRET_ID" \
  --macsec-ckn-secret-identifier "$CKN_SECRET_ID"

echo "MACsec update submitted. Verify both links and traffic before closing the maintenance window."
