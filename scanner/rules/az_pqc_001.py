"""AZ-PQC-001: App Service TLS below 1.3."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-PQC-001"
RULE_NAME = "TLS Using Classical Key Exchange Algorithm"
SEVERITY = "HIGH"
CATEGORY = "PostQuantum"
FRAMEWORKS = {
    "CIS": "9.1",
    "NIST": "PR.DS-2",
    "ISO27001": "A.10.1.1",
    "SOC2": "CC6.7",
}
DESCRIPTION = (
    "The resource is configured with TLS using classical key exchange algorithms "
    "such as RSA or ECDH. These algorithms are vulnerable to Harvest Now Decrypt "
    "Later attacks where adversaries collect encrypted traffic today and decrypt "
    "it once quantum computers are available. Post-quantum safe key exchange "
    "algorithms should be used."
)
REMEDIATION = (
    "Migrate TLS configuration to use post-quantum safe key exchange. Update App "
    "Service TLS policies to enforce TLS 1.3 and plan adoption of quantum-safe "
    "cipher suites when supported. See playbooks/cli/fix_az_pqc_001.sh for "
    "remediation steps."
)
PLAYBOOK = "playbooks/cli/fix_az_pqc_001.sh"

logger = logging.getLogger(__name__)


def _tls_version_below_13(version: Any) -> bool:
    if version is None:
        return False
    try:
        major, minor = str(version).split(".", maxsplit=1)
        return (int(major), int(minor)) < (1, 3)
    except (TypeError, ValueError):
        return str(version) < "1.3"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Scan App Services for TLS versions below 1.3."""
    findings: List[Dict[str, Any]] = []

    web_apps = azure_client.get_web_apps()
    if web_apps is None:
        logger.warning("AZ-PQC-001 skipped: unable to list web apps.")
        return findings

    for app in web_apps:
        app_id = getattr(app, "id", "") or ""
        parsed = azure_client.parse_resource_id(app_id)
        site_config = getattr(app, "site_config", None)
        min_tls = getattr(site_config, "min_tls_version", None) if site_config else None

        if _tls_version_below_13(min_tls):
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": app_id,
                "resource_name": getattr(app, "name", ""),
                "resource_type": "Microsoft.Web/sites",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": parsed.get("resource_group", ""),
                    "min_tls_version": str(min_tls),
                },
            })

    return findings
