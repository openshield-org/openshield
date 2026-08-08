#!/bin/bash
# Shared safety gate for enterprise-resilience remediations.
set -euo pipefail
RULE_ID=${1:-}; RESOURCE_ID=${2:-}
if [ -z "$RULE_ID" ] || [ -z "$RESOURCE_ID" ]; then echo "Usage: $0 <rule-id> <azure-resource-id>"; exit 1; fi
az account show --output none
az resource show --ids "$RESOURCE_ID" --output none
echo "Rule: $RULE_ID"
echo "WARNING: Network and backup changes can interrupt production or become irreversible."
echo "Validate private DNS, routing, clients, backup policies, and rollback procedures first."
read -r -p "Type APPLY to confirm that the target and impact were reviewed: " CONFIRM
[ "$CONFIRM" = "APPLY" ] || { echo "Cancelled."; exit 1; }
case "$RULE_ID" in
  AZ-FUNC-001) az resource update --ids "$RESOURCE_ID" --set properties.httpsOnly=true --output none ;;
  AZ-FUNC-002) az resource update --ids "$RESOURCE_ID/config/web" --set properties.minTlsVersion=1.2 --output none ;;
  AZ-FUNC-003) az resource update --ids "$RESOURCE_ID/config/web" --set properties.ftpsState=Disabled --output none ;;
  AZ-FUNC-004) az resource update --ids "$RESOURCE_ID/config/web" --set properties.remoteDebuggingEnabled=false --output none ;;
  AZ-FUNC-005) az webapp identity assign --ids "$RESOURCE_ID" --output none ;;
  *) echo "Review completed. This control needs service-specific DNS, networking, or security-admin inputs; no automatic change was made." ;;
esac
az resource show --ids "$RESOURCE_ID" --output json
