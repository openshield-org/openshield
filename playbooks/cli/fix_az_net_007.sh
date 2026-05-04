#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-NET-007 — Application Gateway without WAF enabled
# Usage: ./fix_az_net_007.sh <resource-group> <app-gateway-name> <waf-policy-name>
# Severity: HIGH

set -e

RESOURCE_GROUP=$1
AGW_NAME=$2
WAF_POLICY=$3

if [ -z "$RESOURCE_GROUP" ] || [ -z "$AGW_NAME" ] || [ -z "$WAF_POLICY" ]; then
  echo "Usage: $0 <resource-group> <app-gateway-name> <waf-policy-name>"
  echo ""
  echo "To create a WAF policy first:"
  echo "  az network application-gateway waf-policy create --resource-group <rg> --name <policy-name>"
  exit 1
fi

echo "Enabling WAF on Application Gateway '$AGW_NAME'..."

az network application-gateway waf-config set \
  --resource-group "$RESOURCE_GROUP" \
  --gateway-name "$AGW_NAME" \
  --enabled true \
  --firewall-mode Prevention \
  --rule-set-type OWASP \
  --rule-set-version 3.2

echo "✅ WAF enabled on $AGW_NAME in Prevention mode with OWASP 3.2 rule set."
echo "⚠️  Monitor WAF logs for false positives before relying on Prevention mode in production."
