from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_private

RULE_ID = "AZ-PE-006"
RULE_NAME = "Private Endpoint Connection Not Approved"
SEVERITY = "MEDIUM"
CATEGORY = "Network"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-PE-006"}
DESCRIPTION = (
    "A private endpoint connection is pending, rejected, or disconnected and does not provide an active private path."
)
REMEDIATION = (
    "Review ownership, approval state, target resource, and private DNS before approving or replacing the connection."
)
PLAYBOOK = "playbooks/cli/fix_az_pe_006.sh"


def scan(azure_client, subscription_id):
    return scan_private(azure_client, globals(), "connection")
