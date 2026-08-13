from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_private

RULE_ID = "AZ-PE-002"
RULE_NAME = "Azure SQL Public Network Access Enabled"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-PE-002"}
DESCRIPTION = (
    "An Azure SQL logical server remains publicly reachable, regardless of whether a private endpoint also exists."
)
REMEDIATION = "Validate private DNS and clients before disabling public access."
PLAYBOOK = "playbooks/cli/fix_az_pe_002.sh"


def scan(azure_client, subscription_id):
    return scan_private(azure_client, globals(), "sql")
