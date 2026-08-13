from scanner.rules._enterprise_resilience_common import FRAMEWORKS, scan_private

RULE_ID = "AZ-PE-005"
RULE_NAME = "Recovery Vault Public Network Access Enabled"
SEVERITY = "HIGH"
CATEGORY = "Network"
FRAMEWORKS = {**FRAMEWORKS, "CIS": "N/A-PE-005"}
DESCRIPTION = "A Recovery Services vault permits public access, even if a private endpoint also exists."
REMEDIATION = "Validate Backup private DNS and agents before restricting public access."
PLAYBOOK = "playbooks/cli/fix_az_pe_005.sh"


def scan(azure_client, subscription_id):
    return scan_private(azure_client, globals(), "recovery")
