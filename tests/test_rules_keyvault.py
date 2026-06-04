"""Rule regression tests for AZ-KV-002.

Each test configures a MockAzureClient with a fake Key Vault object and calls
the rule's scan() function directly. No network calls are made.
"""

import scanner.rules.az_kv_002 as az_kv_002
from tests.helpers.mock_azure import make_resource

_REQUIRED_FIELDS = {
    "rule_id", "rule_name", "severity", "category",
    "resource_id", "resource_name", "resource_type",
    "description", "remediation", "playbook", "frameworks", "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _kv_id(name):
    return (
        f"/subscriptions/{_SUB}/resourceGroups/{_RG}"
        f"/providers/Microsoft.KeyVault/vaults/{name}"
    )


def _vault(name, public_access, private_endpoints):
    props = make_resource(
        public_network_access=public_access,
        private_endpoint_connections=private_endpoints,
    )
    return make_resource(
        id=_kv_id(name),
        name=name,
        location="eastus",
        properties=props,
    )


def test_kv_002_compliant_public_access_disabled_returns_no_findings(mock_azure, subscription_id):
    """A Key Vault with public access disabled must produce no findings."""
    mock_azure.set_key_vaults([_vault("kv-private", "Disabled", [])])
    findings = az_kv_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_kv_002_compliant_private_endpoint_present_returns_no_findings(mock_azure, subscription_id):
    """A Key Vault with a private endpoint must produce no findings."""
    endpoint = make_resource(id="pe-connection-001", name="pe-kv-secure")
    mock_azure.set_key_vaults([_vault("kv-with-pe", "Enabled", [endpoint])])
    findings = az_kv_002.scan(mock_azure, subscription_id)
    assert findings == []


def test_kv_002_noncompliant_returns_one_finding(mock_azure, subscription_id):
    """A Key Vault with public access enabled and no private endpoint must produce one finding."""
    mock_azure.set_key_vaults([_vault("kv-public", "Enabled", [])])
    findings = az_kv_002.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    finding = findings[0]
    assert _REQUIRED_FIELDS.issubset(finding.keys())
    assert finding["rule_id"] == "AZ-KV-002"
    assert finding["severity"] == "HIGH"
    assert finding["category"] == "Key Vault"
    assert finding["resource_name"] == "kv-public"
    assert finding["metadata"]["resource_group"] == _RG
