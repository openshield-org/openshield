"""Rule regression tests for AZ-IDN-001.

Each test configures a MockAzureClient with fake role assignment objects and
calls the rule's scan() function directly. No network calls are made.
"""

import scanner.rules.az_idn_001 as az_idn_001
from tests.helpers.mock_azure import make_resource

_REQUIRED_FIELDS = {
    "rule_id", "rule_name", "severity", "category",
    "resource_id", "resource_name", "resource_type",
    "description", "remediation", "playbook", "frameworks", "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_OWNER_ROLE_GUID = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
_CONTRIBUTOR_ROLE_GUID = "b24988ac-6180-42a0-ab88-20f7382dd24c"
_ROLE_DEF_BASE = (
    f"/subscriptions/{_SUB}/providers/Microsoft.Authorization/roleDefinitions"
)


def _assignment(role_guid, principal_id, assign_id):
    return make_resource(
        id=f"/subscriptions/{_SUB}/providers/Microsoft.Authorization/roleAssignments/{assign_id}",
        role_definition_id=f"{_ROLE_DEF_BASE}/{role_guid}",
        principal_id=principal_id,
        scope=f"/subscriptions/{_SUB}",
    )


def test_idn_001_compliant_returns_no_findings(mock_azure, subscription_id):
    """A service principal with a non-Owner role must produce no findings."""
    assignment = _assignment(_CONTRIBUTOR_ROLE_GUID, "sp-contributor-abc123", "assign-001")
    mock_azure.set_service_principals([assignment])
    findings = az_idn_001.scan(mock_azure, subscription_id)
    assert findings == []


def test_idn_001_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A service principal holding the Owner role must produce exactly one finding."""
    assignment = _assignment(_OWNER_ROLE_GUID, "sp-owner-def456", "assign-002")
    mock_azure.set_service_principals([assignment])
    findings = az_idn_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-IDN-001"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Identity"
    assert finding["resource_name"] == "sp-owner-def456"
    assert finding["metadata"]["principal_id"] == "sp-owner-def456"
