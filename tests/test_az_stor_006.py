"""Rule tests for AZ-STOR-006: HTTPS-only enforcement for storage accounts.

These tests follow the same style as other storage rule tests in
[tests/test_rules_storage.py](/C:/Users/ACER/openshield/openshield/tests/test_rules_storage.py).
"""

import scanner.rules.az_stor_006 as az_stor_006
from tests.helpers.mock_azure import make_resource

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _storage_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Storage/storageAccounts/{name}"


def test_az_stor_006_compliant_returns_no_findings(mock_azure, subscription_id):
    """A storage account with HTTPS-only enabled must produce no findings."""
    acct = make_resource(
        id=_storage_id("https-only-storage"),
        name="https-only-storage",
        properties={"supportsHttpsTrafficOnly": True},
    )
    mock_azure.set_storage_accounts([acct])
    findings = az_stor_006.scan(mock_azure, subscription_id)
    assert findings == []


def test_az_stor_006_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A storage account that allows HTTP traffic must produce exactly one finding."""
    acct = make_resource(
        id=_storage_id("http-allowed-storage"),
        name="http-allowed-storage",
        properties={"supportsHttpsTrafficOnly": False},
    )
    mock_azure.set_storage_accounts([acct])
    findings = az_stor_006.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    # basic schema checks similar to tests/test_rules_storage.py
    assert finding["rule_id"] == "AZ-STOR-006"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Storage"
    assert finding["resource_name"] == "http-allowed-storage"
    # message/description compatibility
    text = finding.get("message") or finding.get("description", "")
    assert "https" in text.lower()


def test_az_stor_006_unknown_status_skips(mock_azure, subscription_id):
    """If the HTTPS status cannot be determined, the rule must not flag the resource."""
    acct = make_resource(
        id=_storage_id("unknown-storage"),
        name="unknown-storage",
        properties={"supportsHttpsTrafficOnly": None},
    )
    mock_azure.set_storage_accounts([acct])
    findings = az_stor_006.scan(mock_azure, subscription_id)
    assert findings == []
