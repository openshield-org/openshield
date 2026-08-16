"""AZ-NET-021: Private Endpoint FQDN has no private address evidence."""

import logging
from typing import Any, Dict, List

from scanner.rules._private_link_common import evidence, private_address

RULE_ID = "AZ-NET-021"
RULE_NAME = "Private Endpoint FQDN Does Not Resolve to a Private Address"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {"CIS": "N/A-NET-021", "NIST": "PR.AC-5", "ISO27001": "A.13.1.1", "SOC2": "CC6.6"}
DESCRIPTION = "Azure's Private Endpoint DNS configuration reports an FQDN with only public address results."
REMEDIATION = (
    "Correct the Private DNS zone records and VNet links so the endpoint FQDN "
    "resolves to its allocated private IP address."
)
PLAYBOOK = "playbooks/cli/fix_az_net_021.sh"
logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    inventory = azure_client.get_private_link_inventory()
    if inventory is None:
        logger.warning("%s UNKNOWN: Private Endpoint inventory unavailable", RULE_ID)
        return []
    findings = []
    for item in inventory:
        configs = item.get("dns_configs")
        if not configs:
            logger.warning(
                "%s UNKNOWN for %s: FQDN resolution evidence unavailable", RULE_ID, item.get("endpoint_name")
            )
            continue
        bad = []
        for config in configs:
            addresses = [private_address(value) for value in config.get("ip_addresses", [])]
            if (
                config.get("fqdn")
                and addresses
                and all(value is not None for value in addresses)
                and not any(addresses)
            ):
                bad.append(config)
        if not bad:
            continue
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": item.get("endpoint_id", ""),
                "resource_name": item.get("endpoint_name", ""),
                "resource_type": "Microsoft.Network/privateEndpoints",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": evidence(item, {"non_private_dns_results": bad}, {"fqdn_result": "Private IP address"}),
            }
        )
    return findings
