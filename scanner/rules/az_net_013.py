"""AZ-NET-013: Azure Firewall not enabled on Virtual Network."""
from typing import Any, Dict, List

RULE_ID = "AZ-NET-013"
RULE_NAME = "Azure Firewall Not Enabled on Virtual Network"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {
    "CIS": "6.4",
    "NIST": "PR.AC-5",
    "ISO27001": "A.13.1.1",
    "SOC2": "CC6.6"
}
DESCRIPTION = (
    "The Virtual Network does not have an Azure Firewall deployed. "
    "Without Azure Firewall, the VNet relies solely on Network Security "
    "Groups for perimeter defence, which provides no deep packet "
    "inspection, threat intelligence filtering, or centralised traffic "
    "logging. This leaves the network vulnerable to lateral movement "
    "and data exfiltration."
)
REMEDIATION = (
    "Deploy an Azure Firewall in a dedicated AzureFirewallSubnet within "
    "the Virtual Network. Configure network and application rules to "
    "control inbound and outbound traffic. Enable diagnostic logging to "
    "a Log Analytics workspace."
)
PLAYBOOK = "playbooks/cli/fix_az_net_013.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for vnet in azure_client.get_virtual_networks():
        parsed = azure_client.parse_resource_id(vnet.id)
        resource_group = parsed["resource_group"]
        vnet_name = parsed["name"]
        firewalls = azure_client.get_azure_firewalls(resource_group)
        if not firewalls:
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": vnet.id,
                "resource_name": vnet_name,
                "resource_type": "Microsoft.Network/virtualNetworks",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {"resource_group": resource_group}
            })
    return findings