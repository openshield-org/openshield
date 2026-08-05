#!/bin/bash

set -euo pipefail

ACCOUNT_NAME="${1:-}"
CONTAINER_NAME="${2:-}"

if [[ -z "$ACCOUNT_NAME" || -z "$CONTAINER_NAME" ]]; then
  echo "Usage: $0 <storage-account-name> <container-name>"
  exit 1
fi

echo "Setting public access to Off for container: $CONTAINER_NAME (account: $ACCOUNT_NAME)"

az storage container set-permission \
  --name "$CONTAINER_NAME" \
  --account-name "$ACCOUNT_NAME" \
  --public-access off

echo "Public access disabled successfully."
echo "Next step: confirm no anonymous access policy or SAS token grants broader access than intended."
