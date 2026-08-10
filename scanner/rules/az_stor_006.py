"""AZ-STOR-006: Storage account should enforce HTTPS-only traffic.

This rule implementation is written to be tolerant of both calling
conventions seen in the repository's tests and rule modules:

1. scan(azure_client, subscription_id) — iterates azure_client.get_storage_accounts()
2. scan(cache, resource) — evaluates a single resource object/dict

The function will detect which form was called and behave accordingly.
"""

from typing import Any, Dict, List, Optional

RULE_ID = "AZ-STOR-006"
RULE_NAME = "Storage accounts should enforce HTTPS-only traffic"
SEVERITY = "HIGH"
CATEGORY = "Storage"
FRAMEWORKS = {
    "CIS": "CIS-Azure-1.4.0",
    "NIST": "AC-17",
    "ISO": "A.10.1",
    "SOC2": "CC6.1",
}
REMEDIATION = "Enable httpsOnly on the storage account: az storage account update --name <name> --resource-group <rg> --https-only true"
PLAYBOOK = "playbooks/cli/fix_az_stor_006.sh"
REFERENCES = ["https://learn.microsoft.com/azure/storage/common/secure-your-storage-account"]


def _extract_properties(resource: Any) -> Dict[str, Any]:
    """Return a dict-like view of resource properties regardless of input type."""
    # resource may be a dict-like object with .get or a SimpleNamespace/object
    if resource is None:
        return {}
    if hasattr(resource, "get"):
        # dict-like
        props = resource.get("properties") or {}
        if isinstance(props, dict):
            return props
        # props might be SimpleNamespace
        if hasattr(props, "__dict__"):
            return vars(props)
        return {}

    # object-like
    props_obj = getattr(resource, "properties", None)
    if props_obj is None:
        # maybe flags exist at top-level on the resource
        out: Dict[str, Any] = {}
        for attr in ("supportsHttpsTrafficOnly", "enableHttpsTrafficOnly", "httpsOnly"):
            val = getattr(resource, attr, None)
            if val is not None:
                out[attr] = val
        return out

    # props_obj may be namespace or object
    if hasattr(props_obj, "get"):
        return props_obj
    if hasattr(props_obj, "__dict__"):
        return vars(props_obj)
    return {}


def _is_https_disabled(props: Dict[str, Any]) -> bool:
    """Return True if HTTPS-only is explicitly disabled for the resource."""
    https_only = props.get("supportsHttpsTrafficOnly")
    if https_only is None:
        https_only = props.get("enableHttpsTrafficOnly")
    if https_only is None:
        https_only = props.get("httpsOnly")

    return https_only is False or https_only in ("false", 0)


def _resource_identifiers(resource: Any) -> Dict[str, Optional[str]]:
    if hasattr(resource, "get"):
        return {
            "id": resource.get("id"),
            "name": resource.get("name"),
            "type": resource.get("type"),
        }
    return {"id": getattr(resource, "id", None), "name": getattr(resource, "name", None), "type": getattr(resource, "type", None)}


def scan(cache: Any, resource_or_subscription: Any) -> List[Dict[str, Any]]:
    """Support both scan(azure_client, subscription_id) and scan(cache, resource).

    - If resource_or_subscription is a string, treat it as subscription_id and
      iterate cache.get_storage_accounts().
    - Otherwise treat resource_or_subscription as a single resource object/dict.
    """
    findings: List[Dict[str, Any]] = []

    # Path A: called as scan(azure_client, subscription_id)
    if isinstance(resource_or_subscription, str):
        azure_client = cache
        for account in azure_client.get_storage_accounts():
            props = _extract_properties(account)
            if _is_https_disabled(props):
                ids = _resource_identifiers(account)
                findings.append(
                    {
                        "rule_id": RULE_ID,
                        "rule_name": RULE_NAME,
                        "severity": SEVERITY,
                        "category": CATEGORY,
                        "resource_id": ids.get("id"),
                        "resource_name": ids.get("name"),
                        "resource_type": ids.get("type") or "Microsoft.Storage/storageAccounts",
                        "description": "Storage account does not enforce HTTPS-only traffic (httpsOnly is false).",
                        "remediation": REMEDIATION,
                        "playbook": PLAYBOOK,
                        "frameworks": FRAMEWORKS,
                    }
                )
        return findings

    # Path B: called as scan(cache, resource)
    resource = resource_or_subscription
    props = _extract_properties(resource)
    if _is_https_disabled(props):
        ids = _resource_identifiers(resource)
        findings.append(
            {
                "rule_id": RULE_ID,
                "rule_name": RULE_NAME,
                "severity": SEVERITY,
                "category": CATEGORY,
                "resource_id": ids.get("id"),
                "resource_name": ids.get("name"),
                "resource_type": ids.get("type") or "Microsoft.Storage/storageAccounts",
                "description": "Storage account does not enforce HTTPS-only traffic (httpsOnly is false).",
                "remediation": REMEDIATION,
                "playbook": PLAYBOOK,
                "frameworks": FRAMEWORKS,
            }
        )
    return findings
