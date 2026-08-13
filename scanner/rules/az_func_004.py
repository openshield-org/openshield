"""AZ-FUNC-004: Function App remote debugging is enabled."""

from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_functions

RULE_ID = "AZ-FUNC-004"
RULE_NAME = "Function App Remote Debugging Enabled"
SEVERITY = "HIGH"
CATEGORY = "Serverless"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-FUNC-004"}
DESCRIPTION = "Remote debugging expands the Function App management attack surface."
REMEDIATION = "Disable remote debugging outside a controlled troubleshooting window."
PLAYBOOK = "playbooks/cli/fix_az_func_004.sh"


def scan(azure_client, subscription_id):
    return scan_functions(azure_client, globals(), "remote_debugging_enabled", lambda v: v is True)
