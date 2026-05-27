#!/bin/bash
# fix_az_cmp_004.sh
# Enables automatic OS patching on a VM (Windows or Linux)
# Usage: ./fix_az_cmp_004.sh <resource-group> <vm-name> [windows|linux]
# Defaults to windows if OS type is not passed

set -euo pipefail

RG=$1
VM=$2
OS=${3:-windows}

if [ -z "$RG" ] || [ -z "$VM" ]; then
  echo "Usage: $0 <resource-group> <vm-name> [windows|linux]"
  exit 1
fi

if [ "${OS,,}" = "linux" ]; then
  echo "Enabling AutomaticByPlatform patching on Linux VM $VM..."

  az vm update \
    --resource-group "$RG" \
    --name "$VM" \
    --set osProfile.linuxConfiguration.patchSettings.patchMode=AutomaticByPlatform

  echo "Done. Linux VM $VM will now receive automatic OS patches."
else
  echo "Enabling automatic updates on Windows VM $VM..."

  az vm update \
    --resource-group "$RG" \
    --name "$VM" \
    --set osProfile.windowsConfiguration.enableAutomaticUpdates=true \
    --set osProfile.windowsConfiguration.patchSettings.patchMode=AutomaticByPlatform

  echo "Done. Windows VM $VM will now receive automatic OS patches."
fi
