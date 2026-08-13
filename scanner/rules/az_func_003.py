"""AZ-FUNC-003: Function App FTP publishing is enabled."""

from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_functions

RULE_ID = "AZ-FUNC-003"
RULE_NAME = "Function App FTP Publishing Enabled"
SEVERITY = "MEDIUM"
CATEGORY = "Serverless"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-FUNC-003"}
DESCRIPTION = "The Function App exposes an FTP or FTPS deployment channel."
REMEDIATION = "Disable FTP/FTPS publishing after migrating deployment automation."
PLAYBOOK = "playbooks/cli/fix_az_func_003.sh"


def scan(azure_client, subscription_id):
    return scan_functions(azure_client, globals(), "ftps_state", lambda v: str(v).lower() != "disabled")
