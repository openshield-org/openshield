"""Rule regression tests for AZ-STOR-001 and AZ-STOR-002.

Each test configures a MockAzureClient with a single fake storage account
and calls the rule's scan() function directly. No network calls are made.
"""

import scanner.rules.az_stor_001 as az_stor_001
import scanner.rules.az_stor_002 as az_stor_002
import scanner.rules.az_stor_003 as az_stor_003
import scanner.rules.az_stor_004 as az_stor_004
import scanner.rules.az_stor_005 as az_stor_005
from tests.helpers.mock_azure import make_resource

_REQUIRED_FIELDS = {
    "rule_id",
    "rule_name",
    "severity",
    "category",
    "resource_id",
    "resource_name",
    "resource_type",
    "description",
    "remediation",
    "playbook",
    "frameworks",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _storage_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.Storage/storageAccounts/{name}"


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


# ── AZ-STOR-003: no lifecycle management policy ─────────────────────────────


def test_stor_003_compliant_returns_no_findings(mock_azure, subscription_id):
    acct = make_resource(id=_storage_id("sa-lifecycle"), name="sa-lifecycle", location="eastus")
    mock_azure.set_storage_accounts([acct])
    mock_azure.set_storage_lifecycle_policy(_RG, "sa-lifecycle", True)
    assert az_stor_003.scan(mock_azure, subscription_id) == []


def test_stor_003_noncompliant_returns_one_finding(mock_azure, subscription_id):
    acct = make_resource(id=_storage_id("sa-nolifecycle"), name="sa-nolifecycle", location="eastus")
    mock_azure.set_storage_accounts([acct])
    mock_azure.set_storage_lifecycle_policy(_RG, "sa-nolifecycle", False)
    findings = az_stor_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-003"
    assert findings[0]["severity"] == "MEDIUM"


def test_stor_003_indeterminate_skips(mock_azure, subscription_id):
    """When lifecycle status is None (cannot determine) the rule must not flag."""
    acct = make_resource(id=_storage_id("sa-unknown"), name="sa-unknown", location="eastus")
    mock_azure.set_storage_accounts([acct])
    mock_azure.set_storage_lifecycle_policy(_RG, "sa-unknown", None)
    assert az_stor_003.scan(mock_azure, subscription_id) == []


# ── AZ-STOR-004: diagnostic logging disabled (per blob/queue/table) ─────────


def test_stor_004_compliant_all_services_logged_returns_no_findings(mock_azure, subscription_id):
    acct = make_resource(id=_storage_id("sa-logged"), name="sa-logged", location="eastus")
    mock_azure.set_storage_accounts([acct])
    for svc in ("blob", "queue", "table"):
        mock_azure.set_storage_service_logging(_RG, "sa-logged", svc, True)
    assert az_stor_004.scan(mock_azure, subscription_id) == []


def test_stor_004_noncompliant_blob_unlogged_returns_one_finding(mock_azure, subscription_id):
    acct = make_resource(id=_storage_id("sa-blobunlogged"), name="sa-blobunlogged", location="eastus")
    mock_azure.set_storage_accounts([acct])
    mock_azure.set_storage_service_logging(_RG, "sa-blobunlogged", "blob", False)
    mock_azure.set_storage_service_logging(_RG, "sa-blobunlogged", "queue", True)
    mock_azure.set_storage_service_logging(_RG, "sa-blobunlogged", "table", True)
    findings = az_stor_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-004"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["metadata"]["service"] == "blob"


# ── AZ-STOR-005: not geo-redundant ──────────────────────────────────────────


def test_stor_005_compliant_grs_returns_no_findings(mock_azure, subscription_id):
    acct = make_resource(
        id=_storage_id("sa-grs"),
        name="sa-grs",
        location="eastus",
        sku=make_resource(name="Standard_GRS"),
    )
    mock_azure.set_storage_accounts([acct])
    assert az_stor_005.scan(mock_azure, subscription_id) == []


def test_stor_005_noncompliant_lrs_returns_one_finding(mock_azure, subscription_id):
    acct = make_resource(
        id=_storage_id("sa-lrs"),
        name="sa-lrs",
        location="eastus",
        sku=make_resource(name="Standard_LRS"),
    )
    mock_azure.set_storage_accounts([acct])
    findings = az_stor_005.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-STOR-005"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["resource_name"] == "sa-lrs"
