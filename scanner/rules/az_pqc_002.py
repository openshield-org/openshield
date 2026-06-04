"""AZ-PQC-002: Key Vault keys using RSA or ECC algorithms."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-PQC-002"
RULE_NAME = "Key Vault Key Using Non-Quantum-Safe Algorithm"
SEVERITY = "HIGH"
CATEGORY = "PostQuantum"
FRAMEWORKS = {
    "CIS": "8.1",
    "NIST": "PR.DS-2",
    "ISO27001": "A.10.1.1",
    "SOC2": "CC6.7",
}
DESCRIPTION = (
    "The Key Vault contains keys using RSA or ECC algorithms which are vulnerable "
    "to quantum attacks using Shor's algorithm. A sufficiently powerful quantum "
    "computer can break RSA and ECC keys, compromising data encrypted or signed "
    "with these keys. Keys should be migrated to post-quantum safe algorithms "
    "such as those standardised by NIST in FIPS 203, FIPS 204, and FIPS 205."
)
REMEDIATION = (
    "Identify all RSA and ECC keys in Key Vault and plan migration to "
    "post-quantum safe alternatives. For signing use ML-DSA (FIPS 204). For key "
    "encapsulation use ML-KEM (FIPS 203). Document all keys requiring migration "
    "in a Cryptographic Bill of Materials (CBOM). See "
    "playbooks/cli/fix_az_pqc_002.sh for remediation steps."
)
PLAYBOOK = "playbooks/cli/fix_az_pqc_002.sh"

logger = logging.getLogger(__name__)

_CLASSICAL_KEY_TYPES = {"RSA", "EC", "EC-HSM", "RSA-HSM"}


def _key_type_value(key: Any) -> str:
    key_type = getattr(key, "key_type", None)
    return str(getattr(key_type, "value", None) or key_type or "")


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Scan Key Vault keys for non-quantum-safe algorithm usage."""
    findings: List[Dict[str, Any]] = []

    vaults = azure_client.get_key_vaults()
    if vaults is None:
        logger.warning("AZ-PQC-002 skipped: unable to list Key Vaults.")
        return findings

    for vault in vaults:
        vault_id = getattr(vault, "id", "") or ""
        vault_name = getattr(vault, "name", "") or azure_client.parse_resource_id(
            vault_id
        ).get("name", "")
        parsed = azure_client.parse_resource_id(vault_id)
        resource_group = parsed.get("resource_group", "")

        keys = azure_client.get_key_vault_keys(vault_name)
        if keys is None:
            logger.warning("AZ-PQC-002: unable to list keys for vault %s", vault_name)
            continue

        for key in keys:
            key_type = _key_type_value(key)
            if key_type.upper() in _CLASSICAL_KEY_TYPES:
                key_id = getattr(key, "id", "") or f"{vault_id}/keys/{getattr(key, 'name', '')}"
                key_name = getattr(key, "name", "") or key_id.rstrip("/").split("/")[-1]
                findings.append({
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": key_id,
                    "resource_name": key_name,
                    "resource_type": "Microsoft.KeyVault/vaults/keys",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": resource_group,
                        "vault_name": vault_name,
                        "key_type": key_type,
                    },
                })

    return findings
