"""
AZ-STOR-006: Storage account HTTPS-only enforcement disabled
"""

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Required module-level constants ─────────────────────────────────────────

RULE_ID = "AZ-STOR-006"
RULE_NAME = "Storage Account HTTPS Only Enforcement Disabled"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "3.2",
    "NIST": "SC-8",
    "ISO27001": "A.10.1.1",
    "SOC2": "CC6.1",
}
DESCRIPTION = (
    "The storage account does not enforce HTTPS-only traffic. When "
    "`supportsHttpsTrafficOnly` is false, data can be transmitted over "
    "unencrypted HTTP, exposing it to interception and downgrade attacks. "
    "Enforce HTTPS-only to ensure secure transport for storage account traffic."
)
REMEDIATION = (
    "Enable HTTPS-only enforcement on the storage account by setting "
    "`supportsHttpsTrafficOnly` to true. In the Azure portal: Storage Account "
    "> Configuration > Secure transfer required > Enabled. Or use the Azure CLI: "
    "`az storage account update --name <account> --resource-group <rg> --https-only true`."
)
PLAYBOOK = "playbooks/cli/fix_az_stor_006.sh"

# ── Required scan function ───────────────────────────────────────────────────


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect storage accounts with HTTPS-only enforcement disabled.

    For each storage account returned by the azure_client, check the
    `supportsHttpsTrafficOnly` property. If the property is False, emit a
    finding. If the property cannot be determined (permissions or error),
    skip and log a warning to avoid false positives.

    Returns:
        A list of finding dicts for storage accounts where HTTPS-only is not enforced.
    """
    findings: List[Dict[str, Any]] = []

    for account in azure_client.get_storage_accounts():
        resource_id = getattr(account, "id", "")
        account_name = getattr(account, "name", "")
        location = getattr(account, "location", "")

        if not resource_id or not account_name:
            continue

        parsed = azure_client.parse_resource_id(resource_id)
        resource_group = parsed.get("resource_group", "")
        if not resource_group:
            continue

        # azure_client.get_storage_account_properties should return:
        #   True  -> supportsHttpsTrafficOnly is True (compliant)
        #   False -> supportsHttpsTrafficOnly is False (non-compliant)
        #   None  -> could not determine (skip)
        https_only: Optional[bool] = azure_client.get_storage_account_https_only(
            resource_group, account_name
        )

        if https_only is None:
            logger.warning(
                "AZ-STOR-006: Could not determine HTTPS-only status for %s — skipping. "
                "Ensure the service principal has Microsoft.Storage/storageAccounts/read permission.",
                account_name,
            )
            continue

        if https_only is False:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": resource_id,
                    "resource_name": account_name,
                    "resource_type": "Microsoft.Storage/storageAccounts",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "location": location,
                        "supportsHttpsTrafficOnly": False,
                    },
                }
            )

    return findings
