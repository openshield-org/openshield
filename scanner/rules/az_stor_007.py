"""AZ-STOR-007: Storage account permits a TLS version below TLS 1.2."""

import logging
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

RULE_ID = "AZ-STOR-007"
RULE_NAME = "Storage Account Allows TLS Below 1.2"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "N/A-STOR-007",
    "NIST": "N/A-STOR-007",
    "ISO27001": "N/A-STOR-007",
    "SOC2": "N/A-STOR-007",
}
DESCRIPTION = (
    "The storage account permits a minimum TLS version below TLS 1.2. Older "
    "protocols no longer provide an approved transport-security baseline."
)
REMEDIATION = (
    "Set the storage account minimum TLS version to TLS 1.2 or later. Navigate "
    "to Storage Account > Configuration > Minimum TLS version."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_007.sh"

_INSECURE_TLS = {"TLS1_0", "TLS1_1", "1.0", "1.1"}
_SECURE_TLS = {"TLS1_2", "TLS1_3", "1.2", "1.3"}


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Flag explicit TLS 1.0/1.1 values; skip missing or unknown values."""
    findings: List[Dict[str, Any]] = []
    for account in azure_client.get_storage_accounts():
        value = getattr(account, "minimum_tls_version", None)
        if value is None:
            logger.warning("%s: minimum TLS version unavailable; skipping", RULE_ID)
            continue
        normalized = str(value).strip().upper()
        if normalized in _SECURE_TLS or normalized not in _INSECURE_TLS:
            continue
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": account.id,
                "resource_name": account.name,
                "resource_type": "Microsoft.Storage/storageAccounts",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "minimum_tls_version": str(value),
                    "approved_minimum": "TLS1_2",
                },
            }
        )
    return findings
