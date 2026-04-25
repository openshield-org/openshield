#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-DB-001 — PostgreSQL Server Allows Public Network Access
# Usage: ./fix_az_db_001.sh <resource-group> <server-name>
# Severity: HIGH

set -e

RESOURCE_GROUP=$1
RESOURCE_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <server-name>"
  exit 1
fi

echo "Disabling public network access on PostgreSQL server: $RESOURCE_NAME"

az postgres server update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$RESOURCE_NAME" \
  --public-network-access Disabled

echo ""
echo "✅ Remediation complete for $RESOURCE_NAME — public network access is now disabled."
echo "⚠️  Ensure a private endpoint or VNet service endpoint is configured before"
echo "    disabling public access, or applications will lose connectivity."
