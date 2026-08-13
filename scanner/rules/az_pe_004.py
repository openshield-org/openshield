from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_private

RULE_ID = "AZ-PE-004"
RULE_NAME = "Web or Function App Public Network Access Enabled"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-PE-004"}
DESCRIPTION = "An App Service workload remains publicly reachable without a default-deny access policy."
REMEDIATION = "Validate the hosting tier, private DNS, and clients before restricting public access."
PLAYBOOK = "playbooks/cli/fix_az_pe_004.sh"


def scan(azure_client, subscription_id):
    return scan_private(azure_client, globals(), "web")
