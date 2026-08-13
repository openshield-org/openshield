#!/bin/bash
set -euo pipefail
# AZ-SECOPS-007: Show a Defender recommendation so it can be triaged and remediated before its SLA expires
# Usage: ./fix_az_secops_007.sh <assessment-name>
ASSESSMENT_NAME="${1:-}"
if [ -z "$ASSESSMENT_NAME" ]; then
  echo "Usage: $0 <assessment-name>"
  exit 1
fi
echo "Fetching Defender assessment details: $ASSESSMENT_NAME..."
az security assessment show --name "$ASSESSMENT_NAME"
echo ""
echo "Review the recommendation above and remediate the underlying resource misconfiguration."
echo "If remediation is not currently possible, record an approved risk-acceptance exception"
echo "with the security team rather than leaving the recommendation silently unresolved."
