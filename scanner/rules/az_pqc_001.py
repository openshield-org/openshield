"""AZ-PQC-001: App Service TLS below 1.3."""

import logging
from typing import Any, Dict, List, Optional, Tuple

RULE_ID = "AZ-PQC-001"
RULE_NAME = "TLS Using Classical Key Exchange Algorithm"
SEVERITY = "HIGH"
CATEGORY = "PostQuantum"
FRAMEWORKS = {
    "CIS": "9.9",
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


def _parse_version(version: Any) -> Optional[Tuple[int, ...]]:
    """Parse a dotted version string into a tuple of ints for numeric
    comparison, e.g. "1.10" -> (1, 10). Returns None if unparseable."""
    try:
        return tuple(int(part) for part in str(version).split("."))
    except (TypeError, ValueError):
        return None


def _tls_version_below_13(version: Any) -> bool:
    if version is None:
        return False
    parsed = _parse_version(version)
    if parsed is None:
        # Lexicographic string comparison would misorder versions like
        # "1.10" vs "1.3" (a string compare falls to '1' < '3', treating
        # 1.10 as *older* than 1.3). Rather than guess, skip unparseable
        # values instead of flagging or clearing them incorrectly.
        logger.warning("Unrecognized TLS version format %r; skipping", version)
        return False
    return parsed < (1, 3)


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
            findings.append(
                {
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
                }
            )

    return findings
