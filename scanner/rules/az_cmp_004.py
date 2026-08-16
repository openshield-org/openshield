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

# A VM can look compliant by config (auto-updates/AutomaticByPlatform set)
# while still being months behind on real patches, if the platform simply
# hasn't applied anything yet. Real assessment evidence (Azure Update
# Manager / Microsoft.Maintenance, surfaced through the VM's instance view)
# can override a config-only pass into a confirmed finding. It never
# suppresses a config-based finding: config with auto-patching disabled is
# itself an unmanaged-drift risk regardless of today's patch snapshot, so
# the config-flag check always remains the fallback/baseline signal.
ASSESSMENT_OVERRIDE_DESCRIPTION = (
    "VM is configured for automatic OS patching, but its latest Azure Update Manager patch "
    "assessment shows critical or security patches are still pending installation. Config "
    "alone does not prove patches have actually been applied - this is real assessment "
    "evidence that the VM is currently unpatched."
)
ASSESSMENT_OVERRIDE_REMEDIATION = (
    "Trigger an on-demand patch installation (Update Manager > Install now) or review why "
    "the scheduled automatic patching run has not applied the pending critical/security "
    "patches, then re-run the scan to confirm the assessment clears."
)

# An assessment run whose status confirms it actually completed and produced
# real counts. Anything else (in progress, failed, unknown) is not reliable
# enough evidence to override a config-based pass.
_CONCLUSIVE_ASSESSMENT_STATUSES = {"succeeded", "completedwithwarnings"}

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
            findings.append(
                {
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
                        "signal": "config_flags",
                        "determination": "non_compliant",
                    },
                }
            )
            continue

        # Config says patching is enabled - check real assessment evidence
        # for the false-negative case: config correct, platform hasn't
        # actually applied the pending critical/security patches.
        patch_summary = azure_client.get_vm_patch_status(rg, vm_name)
        if patch_summary is None:
            continue

        status = (getattr(patch_summary, "status", "") or "").lower()
        critical_count = getattr(patch_summary, "critical_and_security_patch_count", None)
        if status in _CONCLUSIVE_ASSESSMENT_STATUSES and critical_count is not None and critical_count > 0:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vm.id,
                    "resource_name": vm_name,
                    "resource_type": "Microsoft.Compute/virtualMachines",
                    "description": ASSESSMENT_OVERRIDE_DESCRIPTION,
                    "remediation": ASSESSMENT_OVERRIDE_REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": rg,
                        "signal": "patch_assessment_override",
                        "determination": "non_compliant",
                        "critical_and_security_patch_count": critical_count,
                        "other_patch_count": getattr(patch_summary, "other_patch_count", None),
                        "assessment_status": status,
                    },
                }
            )

    return findings
