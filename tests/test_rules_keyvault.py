"""Rule regression tests for the Key Vault rules AZ-KV-001 .. AZ-KV-005.

Each test configures a MockAzureClient with fake Key Vault data and calls the
rule's scan() function directly. No network calls are made.
"""

from datetime import datetime, timedelta, timezone

import scanner.rules.az_kv_001 as az_kv_001
import scanner.rules.az_kv_002 as az_kv_002
import scanner.rules.az_kv_003 as az_kv_003
import scanner.rules.az_kv_004 as az_kv_004
import scanner.rules.az_kv_005 as az_kv_005
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
    "metadata",
}

_SUB = "00000000-0000-0000-0000-000000000001"
_RG = "rg-test"


def _kv_id(name):
    return f"/subscriptions/{_SUB}/resourceGroups/{_RG}/providers/Microsoft.KeyVault/vaults/{name}"


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
    assert finding["category"] == "KeyVault"
    assert finding["resource_name"] == "kv-public"
    assert finding["metadata"]["resource_group"] == _RG


def _vault_with_props(name, **prop_kwargs):
    return make_resource(
        id=_kv_id(name),
        name=name,
        location="eastus",
        properties=make_resource(**prop_kwargs),
    )


# ── AZ-KV-001: soft delete disabled ─────────────────────────────────────────


def test_kv_001_compliant_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-sd-on", enable_soft_delete=True)])
    assert az_kv_001.scan(mock_azure, subscription_id) == []


def test_kv_001_noncompliant_returns_one_finding(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-sd-off", enable_soft_delete=False, enable_purge_protection=False)])
    findings = az_kv_001.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-KV-001"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["resource_name"] == "kv-sd-off"


# ── AZ-KV-003: diagnostic logging not enabled ───────────────────────────────


def test_kv_003_compliant_returns_no_findings(mock_azure, subscription_id):
    vault = _vault_with_props("kv-diag-on")
    mock_azure.set_key_vaults([vault])
    mock_azure.set_diagnostic_settings(vault.id, True)
    assert az_kv_003.scan(mock_azure, subscription_id) == []


def test_kv_003_noncompliant_returns_one_finding(mock_azure, subscription_id):
    vault = _vault_with_props("kv-diag-off")
    mock_azure.set_key_vaults([vault])
    mock_azure.set_diagnostic_settings(vault.id, False)
    findings = az_kv_003.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-KV-003"
    assert findings[0]["severity"] == "MEDIUM"


def test_kv_003_indeterminate_status_skips(mock_azure, subscription_id):
    """When diagnostic status is None (cannot determine) the rule must not flag."""
    vault = _vault_with_props("kv-diag-unknown")
    mock_azure.set_key_vaults([vault])
    mock_azure.set_diagnostic_settings(vault.id, None)
    assert az_kv_003.scan(mock_azure, subscription_id) == []


# ── AZ-KV-004: purge protection disabled ────────────────────────────────────


def test_kv_004_compliant_returns_no_findings(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-pp-on", enable_purge_protection=True)])
    assert az_kv_004.scan(mock_azure, subscription_id) == []


def test_kv_004_noncompliant_returns_one_finding(mock_azure, subscription_id):
    mock_azure.set_key_vaults([_vault_with_props("kv-pp-off", enable_purge_protection=False)])
    findings = az_kv_004.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-KV-004"
    assert findings[0]["severity"] == "MEDIUM"


# ── AZ-KV-005: certificate expiring within 30 days ──────────────────────────


def test_kv_005_compliant_far_future_expiry_returns_no_findings(mock_azure, subscription_id):
    vault = _vault_with_props("kv-cert-ok")
    mock_azure.set_key_vaults([vault])
    cert = make_resource(
        name="cert-fresh",
        expires_on=datetime.now(timezone.utc) + timedelta(days=200),
        policy=None,
    )
    mock_azure.set_key_vault_certificates("kv-cert-ok", [cert])
    assert az_kv_005.scan(mock_azure, subscription_id) == []


def test_kv_005_noncompliant_expiring_soon_returns_one_finding(mock_azure, subscription_id):
    vault = _vault_with_props("kv-cert-exp")
    mock_azure.set_key_vaults([vault])
    cert = make_resource(
        name="cert-expiring",
        expires_on=datetime.now(timezone.utc) + timedelta(days=10),
        policy=None,
    )
    mock_azure.set_key_vault_certificates("kv-cert-exp", [cert])
    findings = az_kv_005.scan(mock_azure, subscription_id)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-KV-005"
    assert findings[0]["severity"] == "MEDIUM"
    assert findings[0]["resource_name"] == "cert-expiring"
