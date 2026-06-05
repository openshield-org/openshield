"""AZ-PQC-003: Key Vault certificates using classical algorithms."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-PQC-003"
RULE_NAME = "Key Vault Certificate Using Non-Quantum-Safe Signature Algorithm"
SEVERITY = "MEDIUM"
CATEGORY = "PostQuantum"
FRAMEWORKS = {
    "CIS": "8.5",
    "NIST": "PR.DS-2",
    "ISO27001": "A.10.1.1",
    "SOC2": "CC6.7",
}
DESCRIPTION = (
    "The Key Vault contains certificates signed using RSA or ECDSA algorithms. "
    "These classical signature schemes are vulnerable to Shor's algorithm on "
    "quantum computers. Certificates used for authentication, TLS, and code "
    "signing must be migrated to post-quantum safe signature algorithms such "
    "as ML-DSA (FIPS 204) or SLH-DSA (FIPS 205)."
)
REMEDIATION = (
    "Audit all Key Vault certificates and identify those using RSA or ECDSA. "
    "Plan migration to post-quantum safe certificate authorities and signature "
    "algorithms. Include all certificates in your Cryptographic Bill of "
    "Materials. See playbooks/cli/fix_az_pqc_003.sh for remediation steps."
)
PLAYBOOK = "playbooks/cli/fix_az_pqc_003.sh"

logger = logging.getLogger(__name__)

_CLASSICAL_KEY_TYPES = {"RSA", "EC", "EC-HSM", "RSA-HSM"}


def _certificate_key_type(cert: Any) -> str:
    policy = getattr(cert, "policy", None)
    key_props = getattr(policy, "key_properties", None) if policy else None
    key_type = getattr(key_props, "key_type", None) if key_props else None
    return str(getattr(key_type, "value", None) or key_type or "")


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Scan Key Vault certificates for non-quantum-safe algorithms."""
    findings: List[Dict[str, Any]] = []

    vaults = azure_client.get_key_vaults()
    if vaults is None:
        logger.warning("AZ-PQC-003 skipped: unable to list Key Vaults.")
        return findings

    for vault in vaults:
        vault_id = getattr(vault, "id", "") or ""
        vault_name = getattr(vault, "name", "") or azure_client.parse_resource_id(
            vault_id
        ).get("name", "")
        parsed = azure_client.parse_resource_id(vault_id)
        resource_group = parsed.get("resource_group", "")

        certs = azure_client.get_key_vault_certificates(vault_name)
        if certs is None:
            logger.warning(
                "AZ-PQC-003: unable to list certificates for vault %s", vault_name
            )
            continue

        for cert in certs:
            key_type = _certificate_key_type(cert)
            if key_type.upper() in _CLASSICAL_KEY_TYPES:
                cert_id = getattr(cert, "id", "") or f"{vault_id}/certificates/{getattr(cert, 'name', '')}"
                cert_name = getattr(cert, "name", "") or cert_id.rstrip("/").split("/")[-1]
                findings.append({
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": cert_id,
                    "resource_name": cert_name,
                    "resource_type": "Microsoft.KeyVault/vaults/certificates",
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
