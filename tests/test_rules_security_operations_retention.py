"""Tests for AZ-SECOPS-004 (retention) and AZ-SECOPS-005 (destination ownership)."""

from types import SimpleNamespace

import scanner.rules.az_secops_004 as az_secops_004
import scanner.rules.az_secops_005 as az_secops_005
from tests.helpers.mock_azure import MockAzureClient
from tests.helpers.security_operations import (
    diagnostic_setting,
    log_setting,
    make_collector,
    retention_policy,
    set_policy_env,
    stub_collector,
)

_APPROVED = (
    "/subscriptions/sub/resourcegroups/security/providers/microsoft.operationalinsights/workspaces/central-security"
)
_SUB = "00000000-0000-0000-0000-000000000001"
_KV_ID = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1"
_LOCAL_STORAGE = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/localsa"


def _client() -> MockAzureClient:
    return MockAzureClient()


def _resource_inventory():
    return [SimpleNamespace(id=_KV_ID, type="Microsoft.KeyVault/vaults")]


# ── AZ-SECOPS-004: retention boundaries ─────────────────────────────────────


def test_secops_004_retention_at_minimum_is_compliant(monkeypatch, tmp_path):
    """Boundary: exactly the minimum retention must not be flagged."""
    set_policy_env(monkeypatch, tmp_path, minimum_retention_days=90)
    logs = [log_setting(category="AuditEvent", enabled=True, retention_policy=retention_policy(enabled=True, days=90))]
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(
            list=lambda resource_id: [diagnostic_setting(storage_account_id=_LOCAL_STORAGE, logs=logs)]
        )
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_004, collector)
    assert az_secops_004.scan(_client(), _SUB) == []


def test_secops_004_retention_one_day_below_minimum_is_noncompliant(monkeypatch, tmp_path):
    """Boundary: one day below the minimum must be flagged."""
    set_policy_env(monkeypatch, tmp_path, minimum_retention_days=90)
    logs = [log_setting(category="AuditEvent", enabled=True, retention_policy=retention_policy(enabled=True, days=89))]
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(
            list=lambda resource_id: [diagnostic_setting(storage_account_id=_LOCAL_STORAGE, logs=logs)]
        )
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_004, collector)
    findings = az_secops_004.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["retention"][0]["retention_days"] == 89


def test_secops_004_retention_disabled_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, minimum_retention_days=90)
    logs = [
        log_setting(category="AuditEvent", enabled=True, retention_policy=retention_policy(enabled=False, days=365))
    ]
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(
            list=lambda resource_id: [diagnostic_setting(storage_account_id=_LOCAL_STORAGE, logs=logs)]
        )
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_004, collector)
    findings = az_secops_004.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["retention"][0]["retention_enabled"] is False


def test_secops_004_log_analytics_only_export_is_not_evaluated(monkeypatch, tmp_path):
    """Workspace-only exports have no Storage retention_policy semantics; rule must not flag them."""
    set_policy_env(monkeypatch, tmp_path, minimum_retention_days=90)
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(list=lambda resource_id: [diagnostic_setting(workspace_id=_APPROVED)])
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_004, collector)
    assert az_secops_004.scan(_client(), _SUB) == []


def test_secops_004_empty_inventory_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    collector = make_collector(resource_inventory=lambda: [])
    stub_collector(monkeypatch, az_secops_004, collector)
    assert az_secops_004.scan(_client(), _SUB) == []


def test_secops_004_approved_exclusion_suppresses_finding(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, minimum_retention_days=90, approved_exclusions=[_KV_ID])
    logs = [log_setting(category="AuditEvent", enabled=True, retention_policy=retention_policy(enabled=False, days=1))]
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(
            list=lambda resource_id: [diagnostic_setting(storage_account_id=_LOCAL_STORAGE, logs=logs)]
        )
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_004, collector)
    assert az_secops_004.scan(_client(), _SUB) == []


def test_secops_004_permission_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    def fail(resource_id):
        raise PermissionError("denied")

    monitor = SimpleNamespace(diagnostic_settings=SimpleNamespace(list=fail))
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_004, collector)
    assert az_secops_004.scan(_client(), _SUB) == []


# ── AZ-SECOPS-005: destination modifiable by workload administrators ───────


def test_secops_005_approved_destination_present_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(list=lambda resource_id: [diagnostic_setting(workspace_id=_APPROVED)])
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_005, collector)
    assert az_secops_005.scan(_client(), _SUB) == []


def test_secops_005_only_same_resource_group_destination_is_noncompliant(monkeypatch, tmp_path):
    """Destination lives in the same RG as the workload -> workload admin can modify it."""
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(
            list=lambda resource_id: [diagnostic_setting(storage_account_id=_LOCAL_STORAGE)]
        )
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_005, collector)
    findings = az_secops_005.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["ownership"] == "workload-administrator"


def test_secops_005_same_resource_group_event_hub_is_noncompliant(monkeypatch, tmp_path):
    """An Event Hub destination in the workload RG is evaluated like Storage and Log Analytics."""
    set_policy_env(monkeypatch, tmp_path)
    local_event_hub_rule = (
        "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/app-hub/"
        "authorizationRules/diagnostics"
    )
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(
            list=lambda resource_id: [diagnostic_setting(event_hub_authorization_rule_id=local_event_hub_rule)]
        )
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_005, collector)

    findings = az_secops_005.scan(_client(), _SUB)

    assert len(findings) == 1
    assert findings[0]["metadata"]["ownership"] == "workload-administrator"


def test_secops_005_no_export_defers_to_secops_003(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(diagnostic_settings=SimpleNamespace(list=lambda resource_id: []))
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_005, collector)
    assert az_secops_005.scan(_client(), _SUB) == []


def test_secops_005_different_resource_group_destination_is_compliant(monkeypatch, tmp_path):
    """A destination outside the workload's own RG (but not on the approved list) is not flagged
    by this rule even though it's not centrally approved — that gap is AZ-SECOPS-001/003's job."""
    set_policy_env(monkeypatch, tmp_path)
    other_rg_dest = (
        "/subscriptions/sub/resourceGroups/other-team-rg/providers/Microsoft.Storage/storageAccounts/othersa"
    )
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(
            list=lambda resource_id: [diagnostic_setting(storage_account_id=other_rg_dest)]
        )
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_005, collector)
    assert az_secops_005.scan(_client(), _SUB) == []


def test_secops_005_approved_exclusion_suppresses_finding(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, approved_exclusions=[_KV_ID])
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(
            list=lambda resource_id: [diagnostic_setting(storage_account_id=_LOCAL_STORAGE)]
        )
    )
    collector = make_collector(monitor_client=monitor, resource_inventory=_resource_inventory)
    stub_collector(monkeypatch, az_secops_005, collector)
    assert az_secops_005.scan(_client(), _SUB) == []


def test_secops_005_inventory_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    def fail_inventory():
        raise RuntimeError("no access")

    collector = make_collector(resource_inventory=fail_inventory)
    stub_collector(monkeypatch, az_secops_005, collector)
    assert az_secops_005.scan(_client(), _SUB) == []
