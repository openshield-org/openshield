"""AZ-CMP-004: VM without automatic OS patching enabled."""

import logging
from typing import Any, Dict, List

RULE_ID = "AZ-CMP-004"
RULE_NAME = "VM Without Automatic OS Patching Enabled"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {
    "CIS": "8.3",
    "NIST": "PR.IP-12",
    "ISO27001": "A.12.6.1",
    "SOC2": "CC7.1",
}
DESCRIPTION = (
    "VM does not have automatic OS patching enabled. "
    "Unpatched VMs are vulnerable to known exploits. "
    "CIS 8.3 requires OS patches are applied in a timely manner."
)
REMEDIATION = (
    "For Windows VMs enable automatic updates via osProfile.windowsConfiguration "
    "or set patchMode to AutomaticByPlatform. "
    "For Linux VMs set patchMode to AutomaticByPlatform."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_004.sh"

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for vm in azure_client.get_virtual_machines():
        parsed = azure_client.parse_resource_id(getattr(vm, "id", ""))
        rg = parsed.get("resource_group", "")
        vm_name = parsed.get("name", "")
        if not rg or not vm_name:
            continue

        os_profile = getattr(vm, "os_profile", None)
        if not os_profile:
            continue

        patching_ok = False

        win_config = getattr(os_profile, "windows_configuration", None)
        if win_config is not None:
            auto_updates = getattr(win_config, "enable_automatic_updates", False)
            patch_settings = getattr(win_config, "patch_settings", None)
            patch_mode = getattr(patch_settings, "patch_mode", "") if patch_settings else ""
            if auto_updates or (patch_mode or "").lower() == "automaticbyplatform":
                patching_ok = True

        linux_config = getattr(os_profile, "linux_configuration", None)
        if linux_config is not None:
            patch_settings = getattr(linux_config, "patch_settings", None)
            patch_mode = getattr(patch_settings, "patch_mode", "") if patch_settings else ""
            if (patch_mode or "").lower() == "automaticbyplatform":
                patching_ok = True

        if not patching_ok:
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": vm.id,
                "resource_name": vm_name,
                "resource_type": "Microsoft.Compute/virtualMachines",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": rg,
                },
            })

    return findings
