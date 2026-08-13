"""AZ-CMP-001: Virtual machine has a public IP with no associated NSG."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-CMP-001"
RULE_NAME = "VM with Public IP and No Associated NSG on Network Interface"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {"CIS": "7.1", "NIST": "PR.AC-3", "ISO27001": "A.13.1.1"}
DESCRIPTION = (
    "A virtual machine has a public IP address assigned to its network interface "
    "but no Network Security Group protecting that interface. Without an NSG, "
    "all inbound ports are open to the internet by default, creating an unrestricted "
    "attack surface."
)
REMEDIATION = (
    "Associate an NSG with the VM's network interface or its subnet that allows "
    "only required inbound traffic. Remove the public IP if internet access is not needed "
    "and use Azure Bastion or a VPN gateway for administrative access."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_001.sh"

logger = logging.getLogger(__name__)


def _subnet_has_nsg(azure_client: Any, nic: Any) -> bool:
    """Return whether any subnet backing this NIC's IP configurations carries its own NSG.

    A NIC without a NIC-level NSG can still be protected by an NSG attached
    to its subnet - that is a common, valid Azure pattern, not a
    misconfiguration. An unresolvable subnet (missing ID, permissions, SDK
    error) is treated the same as "no subnet NSG" - it must never be read as
    protection, only as "could not confirm", which keeps this check from
    introducing new false negatives.
    """
    for ip_cfg in getattr(nic, "ip_configurations", []) or []:
        subnet_ref = getattr(ip_cfg, "subnet", None)
        subnet_id = getattr(subnet_ref, "id", None)
        if not subnet_id:
            continue

        subnet = azure_client.get_subnet(subnet_id)
        if subnet is not None and getattr(subnet, "network_security_group", None):
            return True

    return False


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect VMs whose NIC has a public IP but no NSG at the NIC or subnet level."""
    findings: List[Dict[str, Any]] = []

    for vm in azure_client.get_virtual_machines():
        network_profile = getattr(vm, "network_profile", None)
        if not network_profile:
            continue

        for nic_ref in getattr(network_profile, "network_interfaces", []) or []:
            nic_id = getattr(nic_ref, "id", "")
            if not nic_id:
                continue

            parsed = azure_client.parse_resource_id(nic_id)
            resource_group = parsed.get("resource_group", "")
            nic_name = parsed.get("name", "")
            if not resource_group or not nic_name:
                continue

            nic = azure_client.get_network_interface(resource_group, nic_name)
            if not nic:
                continue

            has_public_ip = any(
                getattr(ip_cfg, "public_ip_address", None) for ip_cfg in (getattr(nic, "ip_configurations", []) or [])
            )
            has_nic_nsg = bool(getattr(nic, "network_security_group", None))

            has_subnet_nsg = False
            if has_public_ip and not has_nic_nsg:
                has_subnet_nsg = _subnet_has_nsg(azure_client, nic)

            if has_public_ip and not has_nic_nsg and not has_subnet_nsg:
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": vm.id,
                        "resource_name": vm.name,
                        "resource_type": "Microsoft.Compute/virtualMachines",
                        "description": DESCRIPTION,
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                        "metadata": {
                            "nic_id": nic_id,
                            "nic_name": nic_name,
                            "nic_nsg_attached": has_nic_nsg,
                            "subnet_nsg_attached": has_subnet_nsg,
                        },
                    }
                )
                break  # one finding per VM is sufficient

    return findings
