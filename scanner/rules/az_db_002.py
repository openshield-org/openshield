"""AZ-DB-002: Azure SQL server has no auditing configured."""

from typing import Any, Dict, List

RULE_ID = "AZ-DB-002"
RULE_NAME = "Azure SQL Server Has No Auditing Configured"
SEVERITY = "MEDIUM"
CATEGORY = "Database"
FRAMEWORKS = {"CIS": "4.1.3", "NIST": "DE.CM-7", "ISO27001": "A.12.4.1"}
DESCRIPTION = (
    "Azure SQL Server auditing is disabled. Without auditing, database access, "
    "schema changes, and failed login attempts are not logged, making forensic "
    "investigation and compliance reporting impossible."
)
REMEDIATION = (
    "Enable SQL Server auditing and configure a storage account, Log Analytics "
    "workspace, or Event Hub as the audit log destination. "
    "Retain logs for at least 90 days to satisfy most compliance frameworks."
)
PLAYBOOK = "playbooks/cli/fix_az_db_002.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Detect SQL servers where server-level blob auditing is disabled."""
    findings: List[Dict[str, Any]] = []

    for server in azure_client.get_sql_servers():
        parsed = azure_client.parse_resource_id(server.id)
        resource_group = parsed.get("resource_group", "")
        if not resource_group:
            continue

        policy = azure_client.get_sql_server_auditing_policy(resource_group, server.name)
        if policy is None:
            # Could not retrieve policy — treat as unaudited
            is_disabled = True
        else:
            state = str(getattr(policy, "state", "Disabled"))
            is_disabled = state.lower() != "enabled"

        if is_disabled:
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": server.id,
                "resource_name": server.name,
                "resource_type": "Microsoft.Sql/servers",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {
                    "resource_group": resource_group,
                    "auditing_state": getattr(policy, "state", "Unknown") if policy else "Unknown",
                },
            })

    return findings
