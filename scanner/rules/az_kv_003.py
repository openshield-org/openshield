"""AZ-KV-003: Key Vault without diagnostic logging enabled."""

from typing import Any, Dict, List

RULE_ID = "AZ-KV-003"
RULE_NAME = "Key Vault Without Diagnostic Logging Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Key Vault"

FRAMEWORKS = {
    "CIS": "8.4",
    "NIST": "DE.CM-7",
    "ISO27001": "A.12.4.1"
}

DESCRIPTION = (
    "Azure Key Vault diagnostic logging is not enabled. Without diagnostic "
    "logs, access to secrets, keys, and certificates is not recorded, "
    "reducing visibility into unauthorized access attempts and preventing "
    "effective forensic investigation."
)

REMEDIATION = (
    "Enable diagnostic settings for the Key Vault and configure logs to be "
    "sent to Log Analytics, Event Hub, or a Storage Account."
)

PLAYBOOK = "playbooks/cli/fix_az_kv_003.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Key Vaults with missing or disabled diagnostic logging."""
    findings: List[Dict[str, Any]] = []

    for vault in azure_client.get_key_vaults():
        settings = azure_client.get_diagnostic_settings(vault.id)

        logs_enabled = False

        for setting in settings:
            logs = getattr(setting, "logs", None) or []

            for log in logs:
                if getattr(log, "enabled", False):
                    logs_enabled = True
                    break

            if logs_enabled:
                break

        if not settings or not logs_enabled:
            parsed = azure_client.parse_resource_id(vault.id)

            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": vault.id,
                "resource_name": vault.name,
                "resource_type": "Microsoft.KeyVault/vaults",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": parsed.get("resource_group", ""),
                    "location": getattr(vault, "location", ""),
                    "diagnostic_settings_count": len(settings),
                },
            })

    return findings

