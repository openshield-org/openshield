"""AZ-NET-012: NSG flow logs not enabled."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List

RULE_ID = "AZ-NET-012"
RULE_NAME = "NSG Flow Logs Not Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
DESCRIPTION = (
    "Network Security Group flow logs are not enabled. "
    "Without flow logs, network traffic is not auditable and "
    "attacker movement cannot be reconstructed."
)
REMEDIATION = (
    "Enable NSG flow logs to a storage account using Network Watcher. "
    "Run: az network watcher flow-log create --nsg <nsg-name> --enabled true "
    "--storage-account <storage-account-id> --resource-group <rg>"
)
PLAYBOOK = "playbooks/cli/fix_az_net_012.sh"
FRAMEWORKS = {
    "CIS": "6.5",
    "NIST": "DE.CM-1",
    "ISO27001": "A.12.4.1",
    "SOC2": "CC7.2",
}

logger = logging.getLogger(__name__)


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Scan all NSGs and check if flow logs are enabled via Network Watcher."""
    findings: List[Dict[str, Any]] = []

    for nsg in azure_client.get_network_security_groups():
        nsg_id = getattr(nsg, "id", "")
        parsed = azure_client.parse_resource_id(nsg_id)
        resource_group = parsed.get("resource_group", "")
        nsg_name = parsed.get("name", "")

        if not resource_group or not nsg_name:
            continue

        flow_log_enabled = False

        try:
            flow_logs = azure_client.get_nsg_flow_logs(resource_group)
            for flow_log in flow_logs:
                if (
                    getattr(flow_log, "target_resource_id", "") == nsg_id
                    and getattr(flow_log, "enabled", False)
                ):
                    flow_log_enabled = True
                    break
        except Exception:
            flow_log_enabled = False

        if not flow_log_enabled:
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": nsg_id,
                "resource_name": nsg_name,
                "resource_type": "Microsoft.Network/networkSecurityGroups",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "detected_at": datetime.now(timezone.utc).isoformat(),
                "metadata": {
                    "resource_group": resource_group,
                    "flow_logs_enabled": False,
                },
            })

    return findings