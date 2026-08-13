"""AZ-KV-006: Key Vault using legacy access policies instead of Azure RBAC."""

from typing import Any, Dict, List

RULE_ID = "AZ-KV-006"
RULE_NAME = "Key Vault Using Legacy Access Policies Instead of Azure RBAC"
SEVERITY = "MEDIUM"
CATEGORY = "KeyVault"
FRAMEWORKS = {"CIS": "8.6", "NIST": "PR.AC-4", "ISO27001": "A.9.2.3", "SOC2": "CC6.1"}
DESCRIPTION = (
    "The Azure Key Vault is authorizing access through legacy vault access policies "
    "instead of Azure RBAC. Access policies are all-or-nothing per permission type, "
    "cannot be scoped to individual keys/secrets/certificates, are not covered by "
    "Azure RBAC's centralized audit trail (Activity Log role assignments), and are "
    "easy to over-grant since there is no built-in least-privilege role model."
)
REMEDIATION = (
    "Enable Azure RBAC authorization on the Key Vault and replace access policies "
    "with scoped role assignments (e.g. Key Vault Secrets User, Key Vault Crypto Officer). "
    "Note: switching to RBAC does not delete existing access policies, but they stop being enforced."
)
PLAYBOOK = "playbooks/cli/fix_az_kv_006.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect Key Vaults where enable_rbac_authorization is False or None."""
    findings: List[Dict[str, Any]] = []

    for vault in azure_client.get_key_vaults():
        props = getattr(vault, "properties", None)
        if props is None:
            continue

        # Access policies are the legacy default; a vault must opt into RBAC.
        rbac_enabled = getattr(props, "enable_rbac_authorization", False)
        if not rbac_enabled:
            parsed = azure_client.parse_resource_id(vault.id)
            findings.append(
                {
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
                    },
                }
            )

    return findings
