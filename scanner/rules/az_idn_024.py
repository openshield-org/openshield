"""AZ-IDN-024: Workload identities (service principals) excluded from all CA policies."""

from typing import Any, Dict, List

RULE_ID = "AZ-IDN-024"
RULE_NAME = "Workload Identities Excluded From Conditional Access Policies"
SEVERITY = "MEDIUM"
CATEGORY = "Identity"
FRAMEWORKS = {
    "CIS": "N/A-IDN-024",
    "NIST": "PR.AC-4",
    "ISO27001": "A.9.2.3",
    "SOC2": "CC6.3",
}
DESCRIPTION = (
    "All enabled Conditional Access policies that require MFA or other grant controls "
    "explicitly exclude workload identities (service principals). Workload identities "
    "with over-privileged roles that are excluded from access controls represent a "
    "persistent threat vector — if their credentials are compromised, they provide "
    "unrestricted access without any Conditional Access enforcement."
)
REMEDIATION = (
    "Review Conditional Access policies to ensure that workload identities with "
    "privileged roles are not broadly excluded. Use Conditional Access for workload "
    "identities (requires Entra ID P1): Security > Conditional Access > New policy > "
    "set 'Workload identities' as the user type and apply appropriate controls. "
    "At minimum, monitor service principal sign-ins via Identity Protection."
)
PLAYBOOK = "playbooks/cli/fix_az_idn_024.sh"


def _enforcing_policy_excludes_workloads(policy: Dict[str, Any]) -> bool:
    """Return True if an enabled enforcing policy broadly excludes service principals."""
    if policy.get("state") != "enabled":
        return False
    grant = policy.get("grantControls") or {}
    built_in = grant.get("builtInControls") or []
    if not built_in or built_in == ["block"]:
        return False
    conditions = policy.get("conditions") or {}
    users = conditions.get("users") or {}
    excluded_sps = users.get("excludeServicePrincipals") or []
    return "All" in excluded_sps or "GuestsOrExternalUsers" in (users.get("excludeUsers") or [])


def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    policies = azure_client.get_conditional_access_policies()
    if not policies:
        return []

    enforcing = [
        p
        for p in policies
        if p.get("state") == "enabled" and "mfa" in ((p.get("grantControls") or {}).get("builtInControls") or [])
    ]
    if not enforcing:
        return []

    all_exclude_workloads = all(_enforcing_policy_excludes_workloads(p) for p in enforcing)
    if not all_exclude_workloads:
        return []

    return [
        {
            "rule_id": RULE_ID,
            "rule_name": RULE_NAME,
            "severity": SEVERITY,
            "category": CATEGORY,
            "resource_id": f"/tenants/{subscription_id}/conditionalAccess",
            "resource_name": "Conditional Access Policies",
            "resource_type": "Microsoft.AzureActiveDirectory/conditionalAccessPolicies",
            "description": DESCRIPTION,
            "remediation": REMEDIATION,
            "playbook": PLAYBOOK,
            "frameworks": FRAMEWORKS,
            "metadata": {
                "enforcing_policies_count": len(enforcing),
                "all_exclude_workload_identities": True,
            },
        }
    ]
