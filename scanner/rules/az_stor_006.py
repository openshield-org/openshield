"""
Rule ID: AZ-STORAGE-HTTPS-001
Title: Storage Account HTTPS Enforcement
Severity: HIGH
Category: Storage
Description: Detects Azure Storage Accounts that do not enforce HTTPS-only traffic.
"""

def get_storage_accounts(subscription_id):
    """
    Placeholder. The scanner engine will inject real storage accounts.
    Tests will mock this function.
    """
    raise NotImplementedError("Scanner engine must provide storage accounts")

def scan(subscription_id):
    """
    Scans all Storage Accounts in the given subscription
    and returns those that do NOT enforce HTTPS-only.
    """

    storage_accounts = get_storage_accounts(subscription_id)
    findings = []

    for account in storage_accounts:
        props = account.get("properties", {})
        https_only = props.get("supportsHttpsTrafficOnly", True)

        if not https_only:
            findings.append({
                "id": "AZ-STORAGE-HTTPS-001",
                "resource_id": account.get("id"),
                "resource_name": account.get("name"),
                "resource_group": account.get("resourceGroup"),
                "subscription_id": subscription_id,
                "severity": "HIGH",
                "category": "Storage",
                "description": "Storage Account does not enforce HTTPS-only traffic.",
            })

    return findings
