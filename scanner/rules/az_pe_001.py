from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_private

RULE_ID = "AZ-PE-001"
RULE_NAME = "Storage Public Network Access Enabled"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-PE-001"}
DESCRIPTION = (
    "A Storage Account remains publicly reachable; an approved private endpoint alone "
    "does not disable its public endpoint."
)
REMEDIATION = "Validate private DNS and connectivity, add the required endpoint, then restrict public access."
PLAYBOOK = "playbooks/cli/fix_az_pe_001.sh"


def scan(azure_client, subscription_id):
    return scan_private(azure_client, globals(), "storage")
