"""AZ-CMP-003: VM without endpoint protection installed."""

import logging
from typing import Any, Dict, List, Optional, Tuple

RULE_ID = "AZ-CMP-003"
RULE_NAME = "VM Without Endpoint Protection Installed"
SEVERITY = "HIGH"
CATEGORY = "Compute"
FRAMEWORKS = {
    "CIS": "8.2",
    "NIST": "DE.CM-4",
    "ISO27001": "A.12.2.1",
    "SOC2": "CC6.8",
}
DESCRIPTION = (
    "VM has no recognised endpoint protection extension installed. "
    "Without it malware and ransomware can run undetected. "
    "CIS 8.2 requires an approved AV/EDR solution on all VMs."
)
REMEDIATION = "Install IaaSAntimalware or onboard to MDE (MDE.Windows / MDE.Linux) depending on the OS."
PLAYBOOK = "playbooks/cli/fix_az_cmp_003.sh"

# Microsoft Defender for Cloud's "Endpoint protection" assessment reports real
# runtime health of the installed agent - a stronger signal than checking
# whether a named extension is merely present. When Defender confirms
# Unhealthy, that is a confirmed violation even if a recognised extension is
# installed (the earlier, weaker signal this rule used to rely on alone).
DEFENDER_UNHEALTHY_DESCRIPTION = (
    "Microsoft Defender for Cloud reports the 'Endpoint protection' security assessment for "
    "this VM as Unhealthy. This is real agent health telemetry from Defender for Cloud, not "
    "just extension-name presence, so it overrides an otherwise-installed recognised extension."
)
DEFENDER_UNHEALTHY_REMEDIATION = (
    "Open Defender for Cloud > Recommendations > 'Endpoint protection should be installed on "
    "your machines', review why the agent is reporting unhealthy on this VM, and remediate "
    "(reinstall/repair the AV/EDR agent, resolve conflicting security products)."
)

# A recognised EP extension whose provisioning_state is present and is not
# "Succeeded" is not actually protecting the VM - name presence alone was
# the previous (weak) signal. This is surfaced as an indeterminate result,
# not a confirmed absence of endpoint protection, since a transient/failed
# provisioning state does not prove malware protection is truly off.
INDETERMINATE_SEVERITY = "LOW"
INDETERMINATE_DESCRIPTION = (
    "A recognised endpoint protection extension is installed but its provisioning state "
    "indicates it did not complete successfully, so effective protection cannot be "
    "confirmed. This is not a confirmed absence of endpoint protection."
)
INDETERMINATE_REMEDIATION = (
    "Check the extension's status in the Azure Portal (VM > Extensions) and, if failed or "
    "stuck, remove and reinstall it, then re-run the scan to confirm successful provisioning."
)

KNOWN_EP_EXTENSIONS = {
    "microsoftmonitoringagent",
    "mde.linux",
    "mde.windows",
    "iaasantimalware",
}

logger = logging.getLogger(__name__)


def _defender_endpoint_protection_status(azure_client: Any, vm_id: str) -> Optional[bool]:
    """Look up the Defender for Cloud 'Endpoint protection' assessment for a VM.

    The assessments API only supports subscription/management-group scope,
    so this filters the subscription-wide collection down to the one
    matching this VM's resource ID.

    Returns:
        True  - assessment found, status code "Healthy" (confirmed protected).
        False - assessment found, status code "Unhealthy" (confirmed unprotected).
        None  - assessments could not be listed, no assessment matched this
                VM, or its status code was "NotApplicable"/unrecognised.
                Callers must treat this as "Defender signal unavailable" and
                fall back to the extension-based check, never as compliant.
    """
    assessments = azure_client.get_security_assessments()
    if not assessments:
        return None

    vm_id_lower = (vm_id or "").lower()
    for assessment in assessments:
        resource_details = getattr(assessment, "resource_details", None)
        resource_id = (getattr(resource_details, "id", "") or "").lower()
        if resource_id != vm_id_lower:
            continue

        display_name = (getattr(assessment, "display_name", "") or "").lower()
        if "endpoint protection" not in display_name:
            continue

        status = getattr(assessment, "status", None)
        code = (getattr(status, "code", "") or "").lower()
        if code == "healthy":
            return True
        if code == "unhealthy":
            return False
        return None  # NotApplicable or an unrecognised status code

    return None


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for vm in azure_client.get_virtual_machines():
        vm_id = getattr(vm, "id", "")
        parsed = azure_client.parse_resource_id(vm_id)
        rg = parsed.get("resource_group", "")
        vm_name = parsed.get("name", "")
        if not rg or not vm_name:
            continue

        defender_status = _defender_endpoint_protection_status(azure_client, vm_id)

        if defender_status is True:
            continue  # Defender confirms protected - the strongest available signal.

        if defender_status is False:
            findings.append(
                {
                    "rule_id": RULE_ID,
                    "rule_name": RULE_NAME,
                    "severity": SEVERITY,
                    "category": CATEGORY,
                    "resource_id": vm.id,
                    "resource_name": vm_name,
                    "resource_type": "Microsoft.Compute/virtualMachines",
                    "description": DEFENDER_UNHEALTHY_DESCRIPTION,
                    "remediation": DEFENDER_UNHEALTHY_REMEDIATION,
                    "playbook": PLAYBOOK,
                    "frameworks": FRAMEWORKS,
                    "metadata": {
                        "resource_group": rg,
                        "signal": "defender_assessment",
                        "determination": "non_compliant",
                    },
                }
            )
            continue

        # Defender signal unavailable (not onboarded, no assessment yet, API
        # failure) - fall back to the extension-name/provisioning-state check.
        exts = azure_client.get_vm_extensions(rg, vm_name)
        if exts is None:
            continue

        installed: List[Tuple[str, Any]] = []
        for e in exts:
            t = (
                getattr(e, "type_properties_type", None)
                or getattr(e, "virtual_machine_extension_type", None)
                or getattr(e, "type", "")
            )
            if t:
                installed.append((t.lower(), e))

        installed_names = sorted({name for name, _ in installed})
        matched = [(name, ext) for name, ext in installed if name in KNOWN_EP_EXTENSIONS]

        if not matched:
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
                        "installed_extensions": installed_names,
                        "signal": "extension_fallback",
                        "determination": "non_compliant",
                    },
                }
            )
            continue

        # A recognised EP extension is installed - name presence alone is not
        # enough. Where the API exposes provisioning_state, an extension is
        # only treated as healthy when it is unset/unknown (data doesn't
        # support the check - do not invent a new false positive) or equals
        # "Succeeded". Anything else (Failed, Canceled, ...) is surfaced as
        # indeterminate rather than silently passed.
        unhealthy_names = []
        confirmed_healthy = False
        for name, ext in matched:
            provisioning_state = (getattr(ext, "provisioning_state", None) or "").lower()
            if not provisioning_state or provisioning_state == "succeeded":
                confirmed_healthy = True
                break
            unhealthy_names.append(name)

        if confirmed_healthy:
            continue

        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": INDETERMINATE_SEVERITY,
                "category": CATEGORY,
                "resource_id": vm.id,
                "resource_name": vm_name,
                "resource_type": "Microsoft.Compute/virtualMachines",
                "description": INDETERMINATE_DESCRIPTION,
                "remediation": INDETERMINATE_REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": rg,
                    "installed_extensions": installed_names,
                    "unhealthy_extensions": sorted(set(unhealthy_names)),
                    "signal": "extension_fallback",
                    "determination": "indeterminate",
                },
            }
        )

    return findings
