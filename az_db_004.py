"""AZ-DB-004: SQL Server auditing not enabled."""

from typing import Any, Dict, List

RULE_ID = "AZ-DB-004"
RULE_NAME = "SQL Server Auditing Not Enabled"
SEVERITY = "HIGH"
CATEGORY = "Database"
FRAMEWORKS = {
    "CIS": "4.1",
    "NIST": "DE.CM-1",
    "ISO27001": "A.12.4.1"
}
DESCRIPTION = (
    "Azure SQL Servers with auditing disabled produce no activity logs, "
    "making it impossible to detect unauthorized access, privilege "
    "escalation, or suspicious query patterns. Auditing is required "
    "by CIS Azure Benchmark 4.1."
)
REMEDIATION = (
    "Enable auditing on the SQL Server and configure logs to be sent "
    "to a storage account, Log Analytics workspace, or Event Hub."
)
PLAYBOOK = "playbooks/cli/fix_az_db_004.sh"


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return a list of findings. Return [] if no issues are found."""
    findings: List[Dict[str, Any]] = []

    for server in azure_client.get_sql_servers():
        parsed = azure_client.parse_resource_id(server.id)
        resource_group = parsed["resource_group"]
        server_name = parsed["name"]

        policy = azure_client.get_sql_server_auditing_policy(
            resource_group, server_name
        )

        if policy is None or getattr(policy, "state", "Disabled") != "Enabled":
            findings.append({
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": server.id,
                "resource_name": server_name,
                "resource_type": "Microsoft.Sql/servers",
                "description": DESCRIPTION,
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
                "metadata": {}
            })

    return findings