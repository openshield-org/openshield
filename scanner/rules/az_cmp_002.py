"""AZ-CMP-002: Virtual machine OS or data disk using platform-managed encryption only."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-CMP-002"
RULE_NAME = "Virtual machine disk not protected by customer-managed key or ADE"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {"CIS": "7.2", "NIST": "PR.DS-1", "ISO27001": "A.10.1.1", "SOC2": "CC6.7"}
DESCRIPTION = (
    "One or more disks attached to this virtual machine are using platform-managed "
    "encryption only (EncryptionAtRestWithPlatformKey). CIS 7.2 requires disks to be "
    "protected using either Azure Disk Encryption (ADE) or server-side encryption with "
    "a customer-managed key (CMK). Platform-managed encryption does not give the "
    "organisation control over the encryption keys."
)
REMEDIATION = (
    "Configure server-side encryption with a customer-managed key via a Disk Encryption "
    "Set, or enable Azure Disk Encryption on all OS and data disks. Navigate to: "
    "Virtual Machine > Disks > Additional settings > Disk encryption set, or use "
    "az vm encryption enable with a Key Vault."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_002.sh"

logger = logging.getLogger(__name__)


def _disk_needs_flagging(managed_disk: Any) -> bool:
    """Return True only if the disk uses platform-managed encryption.

    Azure platform-managed encryption (EncryptionAtRestWithPlatformKey) is the
    default for all managed disks and does not satisfy CIS 7.2, which requires
    customer-managed keys (CMK) or Azure Disk Encryption (ADE).

    Disks using EncryptionAtRestWithCustomerKey or
    EncryptionAtRestWithPlatformAndCustomerKeys are compliant and should not
    be flagged.
    """
    if managed_disk is None:
        return False

    encryption = getattr(managed_disk, "security_profile", None)
    if encryption is None:
        encryption = getattr(managed_disk, "encryption", None)

    encryption_type = getattr(encryption, "type", None)

    if encryption_type is None:
        return False

    return encryption_type == "EncryptionAtRestWithPlatformKey"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect virtual machines whose disks use platform-managed encryption only."""
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
            managed_disk = getattr(os_disk, "managed_disk", None)
            if _disk_needs_flagging(managed_disk):
                unencrypted_disks.append(
                    getattr(os_disk, "name", "os-disk")
                )

        # Check data disks
        data_disks = getattr(storage_profile, "data_disks", []) or []
        for disk in data_disks:
            managed_disk = getattr(disk, "managed_disk", None)
            if _disk_needs_flagging(managed_disk):
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
