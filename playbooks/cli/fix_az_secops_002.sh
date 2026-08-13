#!/bin/bash
set -euo pipefail
# AZ-SECOPS-002: Enable every required category on the subscription Activity Log diagnostic setting
# Usage: ./fix_az_secops_002.sh <setting-name>
SETTING_NAME="${1:-}"
if [ -z "$SETTING_NAME" ]; then
  echo "Usage: $0 <setting-name>"
  echo "  setting-name is the existing Activity Log diagnostic setting to update."
  exit 1
fi
echo "Enabling all required categories on Activity Log diagnostic setting: $SETTING_NAME..."
az monitor diagnostic-settings subscription update \
  --name "$SETTING_NAME" \
  --logs '[{"category":"Administrative","enabled":true},{"category":"Security","enabled":true},{"category":"Policy","enabled":true},{"category":"ServiceHealth","enabled":true},{"category":"Alert","enabled":true},{"category":"Recommendation","enabled":true}]'
echo "Required categories enabled on: $SETTING_NAME"
