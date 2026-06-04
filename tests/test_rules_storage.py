"""Rule regression tests for AZ-STOR-001 and AZ-STOR-002.

Each test configures a MockAzureClient with a single fake storage account
and calls the rule's scan() function directly. No network calls are made.
"""

import scanner.rules.az_stor_001 as az_stor_001
import scanner.rules.az_stor_002 as az_stor_002
from tests.helpers.mock_azure import make_resource

_REQUIRED_FIELDS = {
    "rule_id", "rule_name", "severity", "category",
    "resource_id", "resource_name", "resource_type",
    "description", "remediation", "playbook", "frameworks",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _storage_id(name):
    return (
        f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
        f"/providers/Microsoft.Storage/storageAccounts/{name}"
    )


def test_stor_001_compliant_returns_no_findings(mock_azure, subscription_id):
    """A storage account with public blob access disabled must produce no findings."""
    account = make_resource(
        id=_storage_id("compliant-storage"),
        name="compliant-storage",
        allow_blob_public_access=False,
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_001.scan(mock_azure, subscription_id)
    assert findings == []


def test_stor_001_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A storage account with public blob access enabled must produce exactly one finding."""
    account = make_resource(
        id=_storage_id("public-storage"),
        name="public-storage",
        allow_blob_public_access=True,
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-STOR-001"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Storage"
    assert finding["resource_name"] == "public-storage"


def test_stor_002_compliant_returns_no_findings(mock_azure, subscription_id):
    """A storage account with HTTPS-only enabled must produce no findings."""
    account = make_resource(
        id=_storage_id("https-only-storage"),
        name="https-only-storage",
        enable_https_traffic_only=True,
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_stor_002_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A storage account that allows HTTP traffic must produce exactly one finding."""
    account = make_resource(
        id=_storage_id("http-allowed-storage"),
        name="http-allowed-storage",
        enable_https_traffic_only=False,
    )
    mock_azure.set_storage_accounts([account])
    findings = az_stor_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-STOR-002"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Storage"
    assert finding["resource_name"] == "http-allowed-storage"
