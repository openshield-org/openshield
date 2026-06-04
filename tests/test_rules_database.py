"""Rule regression tests for AZ-DB-004."""

import scanner.rules.az_db_004 as az_db_004
from tests.helpers.mock_azure import make_resource

_REQUIRED_FIELDS = {
    "rule_id", "rule_name", "severity", "category",
    "resource_id", "resource_name", "resource_type",
    "description", "remediation", "playbook", "frameworks", "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _sql_id(name):
    return (
        f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
        f"/providers/Microsoft.Sql/servers/{name}"
    )


def _firewall_rule(name, start_ip, end_ip):
    return make_resource(
        name=name,
        start_ip_address=start_ip,
        end_ip_address=end_ip,
    )


def test_db_004_compliant_returns_no_findings(mock_azure, subscription_id):
    """A SQL Server with no AllowAzureServices rule must produce no findings."""
    server = make_resource(id=_sql_id("sql-restricted"), name="sql-restricted")
    rule = _firewall_rule("AllowSpecificIP", "203.0.113.10", "203.0.113.10")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_firewall_rules(_RG, "sql-restricted", [rule])
    findings = az_db_004.scan(mock_azure, subscription_id)
    assert findings == []


def test_db_004_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A SQL Server with AllowAllWindowsAzureIps rule must produce exactly one finding."""
    server = make_resource(id=_sql_id("sql-open"), name="sql-open")
    allow_azure = _firewall_rule("AllowAllWindowsAzureIps", "0.0.0.0", "0.0.0.0")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_firewall_rules(_RG, "sql-open", [allow_azure])
    findings = az_db_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-DB-004"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Database"
    assert finding["resource_name"] == "sql-open"
    assert finding["metadata"]["resource_group"] == _RG


def test_db_004_no_firewall_rules_returns_no_findings(mock_azure, subscription_id):
    """A SQL Server with no firewall rules must produce no findings."""
    server = make_resource(id=_sql_id("sql-no-rules"), name="sql-no-rules")
    mock_azure.set_sql_servers([server])
    mock_azure.set_sql_server_firewall_rules(_RG, "sql-no-rules", [])
    findings = az_db_004.scan(mock_azure, subscription_id)
    assert findings == []
