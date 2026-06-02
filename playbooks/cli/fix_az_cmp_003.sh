#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-CMP-003 — VM without endpoint protection installed
# Usage: ./fix_az_cmp_003.sh <resource-group> <vm-name> [windows|linux]
# Severity: HIGH

set -e

RG=$1
VM=$2
OS=${3:-windows}

if [ -z "$RG" ] || [ -z "$VM" ]; then
  echo "Usage: $0 <resource-group> <vm-name> [windows|linux]"
  exit 1
fi

if [ "${OS,,}" = "linux" ]; then
  echo "Installing MDE.Linux on $VM..."
  az vm extension set \
    --resource-group "$RG" \
    --vm-name "$VM" \
    --name "MDE.Linux" \
    --publisher "Microsoft.Azure.AzureDefenderForServers" \
    --version "1.0" \
    --auto-upgrade-minor-version true
  echo "Done. Finish onboarding in the Defender portal."
else
  echo "Enabling IaaSAntimalware on $VM..."
  SETTINGS='{
    "AntimalwareEnabled": true,
    "RealtimeProtectionEnabled": true,
    "ScheduledScanSettings": {
      "isEnabled": true,
      "day": "1",
      "time": "120",
      "scanType": "Quick"
    }
  }'
  az vm extension set \
    --resource-group "$RG" \
    --vm-name "$VM" \
    --name "IaaSAntimalware" \
    --publisher "Microsoft.Azure.Security" \
    --version "1.3" \
    --auto-upgrade-minor-version true \
    --settings "$SETTINGS"
  echo "IaaSAntimalware enabled on $VM."
fi
