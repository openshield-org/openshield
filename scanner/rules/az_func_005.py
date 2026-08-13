"""AZ-FUNC-005: Function App has no managed identity."""

from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_functions

RULE_ID = "AZ-FUNC-005"
RULE_NAME = "Function App Managed Identity Missing"
SEVERITY = "MEDIUM"
CATEGORY = "Serverless"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-FUNC-005"}
DESCRIPTION = "The Function App has no Azure managed identity for secretless resource access."
REMEDIATION = "Assign a managed identity and migrate supported credentials to identity-based access."
PLAYBOOK = "playbooks/cli/fix_az_func_005.sh"


def scan(azure_client, subscription_id):
    return scan_functions(azure_client, globals(), "identity_type", lambda v: str(v).lower() == "none")
