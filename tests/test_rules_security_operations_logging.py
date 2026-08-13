"""Tests for AZ-SECOPS-001..003: activity log export, categories, critical-resource diagnostics."""

from types import SimpleNamespace

import scanner.rules.az_secops_001 as az_secops_001
import scanner.rules.az_secops_002 as az_secops_002
import scanner.rules.az_secops_003 as az_secops_003
from tests.helpers.mock_azure import MockAzureClient
from tests.helpers.security_operations import (
    diagnostic_setting,
    log_setting,
    make_collector,
    set_policy_env,
    stub_collector,
)

_APPROVED = (
    "/subscriptions/sub/resourcegroups/security/providers/microsoft.operationalinsights/workspaces/central-security"
)
_SUB = "00000000-0000-0000-0000-000000000001"


def _client() -> MockAzureClient:
    return MockAzureClient()


# ── AZ-SECOPS-001: subscription activity log export ────────────────────────


def test_secops_001_no_policy_configured_returns_no_findings(monkeypatch):
    monkeypatch.delenv("OPENSHIELD_SECURITY_OPERATIONS_POLICY", raising=False)
    assert az_secops_001.scan(_client(), _SUB) == []


def test_secops_001_approved_export_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(
        subscription_diagnostic_settings=SimpleNamespace(list=lambda: [diagnostic_setting(workspace_id=_APPROVED)])
    )
    stub_collector(monkeypatch, az_secops_001, make_collector(monitor_client=monitor))
    assert az_secops_001.scan(_client(), _SUB) == []


def test_secops_001_no_export_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(subscription_diagnostic_settings=SimpleNamespace(list=lambda: []))
    stub_collector(monkeypatch, az_secops_001, make_collector(monitor_client=monitor))
    findings = az_secops_001.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "AZ-SECOPS-001"
    assert findings[0]["metadata"]["destination"] == "none-approved"
    assert findings[0]["metadata"]["confidence"] == "HIGH"


def test_secops_001_export_to_unapproved_destination_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(
        subscription_diagnostic_settings=SimpleNamespace(
            list=lambda: [diagnostic_setting(workspace_id="/subscriptions/sub/workspaces/unapproved")]
        )
    )
    stub_collector(monkeypatch, az_secops_001, make_collector(monitor_client=monitor))
    findings = az_secops_001.scan(_client(), _SUB)
    assert len(findings) == 1


def test_secops_001_collection_failure_is_unknown_not_fail(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    def fail():
        raise PermissionError("no access")

    monitor = SimpleNamespace(subscription_diagnostic_settings=SimpleNamespace(list=fail))
    stub_collector(monkeypatch, az_secops_001, make_collector(monitor_client=monitor))
    assert az_secops_001.scan(_client(), _SUB) == []


# ── AZ-SECOPS-002: required activity-log categories ─────────────────────────


def test_secops_002_all_categories_enabled_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    logs = [log_setting(category=c, enabled=True) for c in ("Administrative", "Security", "Policy", "ServiceHealth")]
    monitor = SimpleNamespace(
        subscription_diagnostic_settings=SimpleNamespace(
            list=lambda: [diagnostic_setting(workspace_id=_APPROVED, logs=logs)]
        )
    )
    stub_collector(monkeypatch, az_secops_002, make_collector(monitor_client=monitor))
    assert az_secops_002.scan(_client(), _SUB) == []


def test_secops_002_missing_category_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    logs = [log_setting(category=c, enabled=True) for c in ("Administrative", "Security")]
    monitor = SimpleNamespace(
        subscription_diagnostic_settings=SimpleNamespace(
            list=lambda: [diagnostic_setting(workspace_id=_APPROVED, logs=logs)]
        )
    )
    stub_collector(monkeypatch, az_secops_002, make_collector(monitor_client=monitor))
    findings = az_secops_002.scan(_client(), _SUB)
    assert len(findings) == 1
    assert set(findings[0]["metadata"]["category"]) == {"policy", "servicehealth"}


def test_secops_002_disabled_category_counts_as_missing(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    logs = [
        log_setting(category="Administrative", enabled=True),
        log_setting(category="Security", enabled=False),
        log_setting(category="Policy", enabled=True),
        log_setting(category="ServiceHealth", enabled=True),
    ]
    monitor = SimpleNamespace(
        subscription_diagnostic_settings=SimpleNamespace(
            list=lambda: [diagnostic_setting(workspace_id=_APPROVED, logs=logs)]
        )
    )
    stub_collector(monkeypatch, az_secops_002, make_collector(monitor_client=monitor))
    findings = az_secops_002.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["category"] == ["security"]


def test_secops_002_no_approved_export_defers_to_secops_001(monkeypatch, tmp_path):
    """When there's no approved-destination export at all, AZ-SECOPS-001 owns that finding."""
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(subscription_diagnostic_settings=SimpleNamespace(list=lambda: []))
    stub_collector(monkeypatch, az_secops_002, make_collector(monitor_client=monitor))
    assert az_secops_002.scan(_client(), _SUB) == []


def test_secops_002_collection_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    def fail():
        raise RuntimeError("boom")

    monitor = SimpleNamespace(subscription_diagnostic_settings=SimpleNamespace(list=fail))
    stub_collector(monkeypatch, az_secops_002, make_collector(monitor_client=monitor))
    assert az_secops_002.scan(_client(), _SUB) == []


# ── AZ-SECOPS-003: critical resource diagnostics ────────────────────────────

_KV_ID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"


def _resource_inventory():
    return [SimpleNamespace(id=_KV_ID, type="Microsoft.KeyVault/vaults")]


def test_secops_003_empty_inventory_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    collector = make_collector(resource_inventory=lambda: [])
    stub_collector(monkeypatch, az_secops_003, collector)
    assert az_secops_003.scan(_client(), _SUB) == []


def test_secops_003_critical_resource_with_approved_export_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(list=lambda resource_id: [diagnostic_setting(workspace_id=_APPROVED)])
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_003, collector)
    assert az_secops_003.scan(_client(), _SUB) == []


def test_secops_003_critical_resource_with_no_export_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(diagnostic_settings=SimpleNamespace(list=lambda resource_id: []))
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_003, collector)
    findings = az_secops_003.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["resource_id"] == _KV_ID
    assert findings[0]["metadata"]["destination"] == "none-approved"


def test_secops_003_approved_exclusion_suppresses_finding(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, approved_exclusions=[_KV_ID])
    monitor = SimpleNamespace(diagnostic_settings=SimpleNamespace(list=lambda resource_id: []))
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_003, collector)
    assert az_secops_003.scan(_client(), _SUB) == []


def test_secops_003_inventory_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    def fail_inventory():
        raise RuntimeError("no access")

    collector = make_collector(resource_inventory=fail_inventory)
    stub_collector(monkeypatch, az_secops_003, collector)
    assert az_secops_003.scan(_client(), _SUB) == []


def test_secops_003_diagnostic_settings_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    def fail_list(resource_id):
        raise PermissionError("denied")

    monitor = SimpleNamespace(diagnostic_settings=SimpleNamespace(list=fail_list))
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_003, collector)
    assert az_secops_003.scan(_client(), _SUB) == []
