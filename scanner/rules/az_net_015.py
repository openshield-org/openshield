"""AZ-NET-015: Public DNS zone exposes internal infrastructure to enumeration."""
from typing import Any, Dict, List

RULE_ID = "AZ-NET-015"
RULE_NAME = "Public DNS Zone Exposes Infrastructure to Enumeration"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
FRAMEWORKS = {
    "CIS": "9.2",
    "NIST": "PR.AC-5",
    "ISO27001": "A.13.1.1",
    "SOC2": "CC6.6"
}
DESCRIPTION = (
    "The DNS zone is configured as a Public zone, meaning its records "
    "are queryable by anyone on the internet. Public DNS zones expose "
    "internal hostnames, IP addresses, and service endpoints to "
    "enumeration, which can assist attackers in mapping the organisation's "
    "infrastructure and identifying targets for further attack."
)
REMEDIATION = (
    "Review all DNS zones and migrate records for internal services to "
    "Azure Private DNS zones linked to the appropriate virtual networks. "
    "Retain public DNS zones only for resources that are intentionally "
    "internet-facing and require public resolution."
)
PLAYBOOK = "playbooks/cli/fix_az_net_015.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for zone in azure_client.get_dns_zones():
        parsed = azure_client.parse_resource_id(zone.id)
        resource_group = parsed["resource_group"]
        zone_type = getattr(zone, "zone_type", "Public")
        if zone_type == "Public":
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": zone.id,
                "resource_name": zone.name,
                "resource_type": "Microsoft.Network/dnsZones",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": resource_group,
                    "zone_type": zone_type
                }
            })
    return findings