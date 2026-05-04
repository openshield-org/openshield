#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-NET-009 — VPN gateway using outdated IKE version
# Usage: ./fix_az_net_009.sh <resource-group> <connection-name>
# Severity: HIGH

set -e

RESOURCE_GROUP=$1
CONNECTION_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$CONNECTION_NAME" ]; then
  echo "Usage: $0 <resource-group> <connection-name>"
  exit 1
fi

echo "Updating VPN connection '$CONNECTION_NAME' to use IKEv2..."

az network vpn-connection update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$CONNECTION_NAME" \
  --set connectionProtocol=IKEv2

echo "✅ VPN connection '$CONNECTION_NAME' updated to IKEv2."
echo "⚠️  Ensure the remote VPN peer also supports IKEv2 before applying this change."
echo "⚠️  The VPN connection will briefly disconnect during the update."
