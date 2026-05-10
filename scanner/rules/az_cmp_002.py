"""AZ-CMP-002: Virtual machine without disk encryption enabled."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-CMP-002"
RULE_NAME = "Virtual machine without disk encryption enabled"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {"CIS": "7.2", "NIST": "PR.DS-1", "ISO27001": "A.10.1.1"}
DESCRIPTION = (
    "One or more disks attached to this virtual machine are not encrypted "
    "using Azure Disk Encryption or server-side encryption with a "
    "customer-managed key. An attacker who gains subscription-level access "
    "can snapshot an unencrypted disk and mount it on another VM to read "
    "all data without needing the original VM credentials."
)
REMEDIATION = (
    "Enable Azure Disk Encryption on all OS and data disks attached to the "
    "virtual machine. Navigate to: Virtual Machine > Disks > Additional settings "
    "> Disk encryption. Alternatively, configure server-side encryption with "
    "customer-managed keys via a Disk Encryption Set."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_002.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect virtual machines with unencrypted OS or data disks."""
    findings: List[Dict[str, Any]] = []

    for vm in azure_client.get_virtual_machines():
        vm_id = getattr(vm, "id", "")
        vm_name = getattr(vm, "name", "")
        location = getattr(vm, "location", "")

        if not vm_id or not vm_name:
            continue

        parsed = azure_client.parse_resource_id(vm_id)
        resource_group = parsed.get("resource_group", "")

        storage_profile = getattr(vm, "storage_profile", None)
        if not storage_profile:
            continue

        unencrypted_disks = []

        # Check OS disk
        os_disk = getattr(storage_profile, "os_disk", None)
        if os_disk:
            encryption = getattr(os_disk, "managed_disk", None)
            disk_encryption_set = getattr(
                encryption, "disk_encryption_set_id", None
            ) if encryption else None
            security_profile = getattr(os_disk, "encryption_settings_collection", None)
            if not disk_encryption_set and not security_profile:
                unencrypted_disks.append(getattr(os_disk, "name", "os-disk"))

        # Check data disks
        data_disks = getattr(storage_profile, "data_disks", []) or []
        for disk in data_disks:
            encryption = getattr(disk, "managed_disk", None)
            disk_encryption_set = getattr(
                encryption, "disk_encryption_set_id", None
            ) if encryption else None
            security_profile = getattr(disk, "encryption_settings_collection", None)
            if not disk_encryption_set and not security_profile:
                unencrypted_disks.append(
                    getattr(disk, "name", f"data-disk-{getattr(disk, 'lun', '?')}")
                )

        if unencrypted_disks:
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": vm_id,
                "resource_name": vm_name,
                "resource_type": "Microsoft.Compute/virtualMachines",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": resource_group,
                    "location": location,
                    "unencrypted_disks": unencrypted_disks,
                    "unencrypted_disk_count": len(unencrypted_disks),
                },
            })

    return findings
