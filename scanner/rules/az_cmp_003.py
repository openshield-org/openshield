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
REMEDIATION = (
    "Install IaaSAntimalware or onboard to MDE (MDE.Windows / MDE.Linux) "
    "depending on the OS."
)
PLAYBOOK = "playbooks/cli/fix_az_cmp_003.sh"

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

        installed = set()
        for e in exts:
            t = (
                getattr(e, "type_properties_type", None)
                or getattr(e, "virtual_machine_extension_type", None)
                or getattr(e, "type", "")
            )
            if t:
                installed.add(t.lower())

        if not installed.intersection(KNOWN_EP_EXTENSIONS):
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
                    "installed_extensions": sorted(installed),
                },
            })

    return findings
