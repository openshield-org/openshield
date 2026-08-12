#!/usr/bin/env bash
# Remove an explicit default route that uses the Internet next hop.
set -euo pipefail

RESOURCE_GROUP="${1:-}"
ROUTE_TABLE_NAME="${2:-}"
ROUTE_NAME="${3:-}"

if [[ -z "$RESOURCE_GROUP" || -z "$ROUTE_TABLE_NAME" || -z "$ROUTE_NAME" ]]; then
  echo "Usage: $0 <resource-group> <route-table-name> <route-name>"
  exit 1
fi

echo "Review dependent subnet egress before removing route $ROUTE_NAME."
read -r -p "Remove the direct Internet route? [y/N] " CONFIRM
if [[ "$CONFIRM" != "y" && "$CONFIRM" != "Y" ]]; then
  echo "No change made."
  exit 0
fi

az network route-table route delete \
  --resource-group "$RESOURCE_GROUP" \
  --route-table-name "$ROUTE_TABLE_NAME" \
  --name "$ROUTE_NAME"

echo "Route $ROUTE_NAME removed. Configure the approved inspected egress route before restoring traffic."
