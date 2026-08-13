#!/bin/bash
set -euo pipefail
# AZ-SECOPS-006: Enable a required Microsoft Defender for Cloud plan at subscription scope
# Usage: ./fix_az_secops_006.sh <plan-name>
# plan-name examples: VirtualMachines, StorageAccounts, SqlServers, KeyVaults, AppServices
PLAN_NAME="${1:-}"
if [ -z "$PLAN_NAME" ]; then
  echo "Usage: $0 <plan-name>"
  echo "  plan-name examples: VirtualMachines, StorageAccounts, SqlServers, KeyVaults, AppServices"
  exit 1
fi
echo "WARNING: Enabling Microsoft Defender for Cloud plan '$PLAN_NAME' incurs additional cost."
echo "Enabling Defender plan: $PLAN_NAME..."
az security pricing create --name "$PLAN_NAME" --tier Standard
echo "Defender plan enabled: $PLAN_NAME"
