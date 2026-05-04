"""AZ-NET-003: NSG allows unrestricted inbound on port 443."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-003"
RULE_NAME = "NSG allows unrestricted inbound on port 443"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "9.3", "NIST": "SC-7", "ISO27001": "A.13.1.1"}
DESCRIPTION = (
    "A Network Security Group has an inbound rule allowing unrestricted access "
    "on port 443 from any source (0.0.0.0/0). While HTTPS traffic is encrypted, "
    "exposing port 443 to the entire internet unnecessarily increases the attack "
    "surface and can expose web services to automated scanning and exploitation attempts."
)
REMEDIATION = (
    "Restrict the inbound rule on port 443 to known IP ranges or use an "
    "Application Gateway with WAF to front any public-facing HTTPS services. "
    "If the service must be public, ensure it is protected by DDoS Standard."
)
PLAYBOOK = "playbooks/cli/fix_az_net_003.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect NSGs with unrestricted inbound access on port 443."""
    findings: List[Dict[str, Any]] = []

    for nsg in azure_client.get_network_security_groups():
        for rule in getattr(nsg, "security_rules", []) or []:
            if (
                getattr(rule, "direction", "") == "Inbound"
                and getattr(rule, "access", "") == "Allow"
                and getattr(rule, "source_address_prefix", "") in ("*", "0.0.0.0/0", "Internet", "Any")
                and getattr(rule, "destination_port_range", "") in ("443", "*")
            ):
                findings.append({
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": getattr(nsg, "id", ""),
                    "resource_name": getattr(nsg, "name", ""),
                    "resource_type": "Microsoft.Network/networkSecurityGroups",
                    "description": DESCRIPTION,
                    "remediation": REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "rule_name": getattr(rule, "name", ""),
                        "source_prefix": getattr(rule, "source_address_prefix", ""),
                    },
                })
                break

    return findings
