#!/bin/bash
# fix_az_kv_005.sh
# Enables auto-renewal on an expiring Key Vault certificate
# Usage: ./fix_az_kv_005.sh <vault-name> <certificate-name>

set -euo pipefail

VAULT=$1
CERT=$2

if [ -z "$VAULT" ] || [ -z "$CERT" ]; then
  echo "Usage: $0 <vault-name> <certificate-name>"
  exit 1
fi

echo "Fetching current policy for certificate $CERT in vault $VAULT..."

POLICY=$(az keyvault certificate policy show \
  --vault-name "$VAULT" \
  --name "$CERT")

echo "Updating certificate policy to enable auto-renewal 30 days before expiry..."

echo "$POLICY" | python3 -c "
import json, sys
policy = json.load(sys.stdin)
policy.setdefault('lifetime_actions', [])
already = any(
    a.get('action', {}).get('action_type') == 'AutoRenew'
    for a in policy['lifetime_actions']
)
if not already:
    policy['lifetime_actions'].append({
        'action': {'action_type': 'AutoRenew'},
        'trigger': {'days_before_expiry': 30}
    })
print(json.dumps(policy))
" | az keyvault certificate policy update \
  --vault-name "$VAULT" \
  --name "$CERT" \
  --policy @-

echo "Done. Certificate $CERT will now auto-renew 30 days before expiry."
echo "Note: Auto-renewal requires the certificate issuer to be configured correctly."
