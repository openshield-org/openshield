"""AZ-NET-005: Virtual network with no DDoS protection enabled."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-NET-005"
RULE_NAME = "Virtual network with no DDoS protection enabled"
SEVERITY = "LOW"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "9.4", "NIST": "SC-5", "ISO27001": "A.13.1.1"}
DESCRIPTION = (
    "The virtual network does not have Azure DDoS Protection Standard enabled. "
    "Without DDoS protection, the network is vulnerable to volumetric attacks "
    "that can overwhelm resources and cause service outages."
)
REMEDIATION = (
    "Enable Azure DDoS Protection Standard on the virtual network. "
    "DDoS Protection Standard provides enhanced mitigation capabilities "
    "and is recommended for all production virtual networks."
)
PLAYBOOK = "playbooks/cli/fix_az_net_005.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect virtual networks without DDoS protection enabled."""
    findings: List[Dict[str, Any]] = []

    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(
            azure_client.credential, azure_client.subscription_id
        )
        vnets = list(client.virtual_networks.list_all())
    except Exception as exc:
        logger.error("Failed to list virtual networks: %s", exc)
        return findings

    for vnet in vnets:
        ddos = getattr(vnet, "ddos_protection_plan", None)
        enable_ddos = getattr(vnet, "enable_ddos_protection", False)
        if not ddos and not enable_ddos:
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": getattr(vnet, "id", ""),
                "resource_name": getattr(vnet, "name", ""),
                "resource_type": "Microsoft.Network/virtualNetworks",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "location": getattr(vnet, "location", ""),
                    "ddos_protection": enable_ddos,
                },
            })

    return findings
