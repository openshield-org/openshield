from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_private

RULE_ID = "AZ-PE-003"
RULE_NAME = "PostgreSQL Public Network Access Enabled"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-PE-003"}
DESCRIPTION = "A PostgreSQL Flexible Server remains publicly reachable instead of using private networking only."
REMEDIATION = "Validate supported networking mode and private DNS before restricting public access."
PLAYBOOK = "playbooks/cli/fix_az_pe_003.sh"


def scan(azure_client, subscription_id):
    return scan_private(azure_client, globals(), "postgresql")
