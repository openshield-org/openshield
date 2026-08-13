"""AZ-CMP-003: VM without endpoint protection installed."""

import logging
from typing import Any, Dict, List

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


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []

    for vm in azure_client.get_virtual_machines():
        parsed = azure_client.parse_resource_id(getattr(vm, "id", ""))
        rg = parsed.get("resource_group", "")
        vm_name = parsed.get("name", "")
        if not rg or not vm_name:
            continue

        exts = azure_client.get_vm_extensions(rg, vm_name)
        if exts is None:
            continue

        installed: Dict[str, Any] = {}
        for e in exts:
            t = (
                getattr(e, "type_properties_type", None)
                or getattr(e, "virtual_machine_extension_type", None)
                or getattr(e, "type", "")
            )
            if t:
                installed[t.lower()] = e

        matched = {name: ext for name, ext in installed.items() if name in KNOWN_EP_EXTENSIONS}

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
                        "installed_extensions": sorted(installed.keys()),
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
        for name, ext in matched.items():
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
                    "installed_extensions": sorted(installed.keys()),
                    "unhealthy_extensions": sorted(unhealthy_names),
                    "determination": "indeterminate",
                },
            }
        )

    return findings
