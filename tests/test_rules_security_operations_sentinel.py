"""Tests for AZ-SECOPS-008 (connector health), AZ-SECOPS-009 (analytics coverage),
and AZ-SECOPS-010 (incident-response destination)."""

from types import SimpleNamespace

import scanner.rules.az_secops_008 as az_secops_008
import scanner.rules.az_secops_009 as az_secops_009
import scanner.rules.az_secops_010 as az_secops_010
from tests.helpers.mock_azure import MockAzureClient
from tests.helpers.security_operations import make_collector, set_policy_env, stub_collector, workspace

_SUB = "00000000-0000-0000-0000-000000000001"


def _client() -> MockAzureClient:
    return MockAzureClient()


def _onboarding_states_list(count: int = 1):
    return SimpleNamespace(value=[SimpleNamespace(name=f"state-{i}") for i in range(count)])


def _sentinel_client(onboarded=True, connectors=None, alert_rules=None, automation_rules=None, raise_onboarding=False):
    def onboarding_list(rg, wn):
        if raise_onboarding:
            raise PermissionError("denied")
        return _onboarding_states_list(1 if onboarded else 0)

    return SimpleNamespace(
        sentinel_onboarding_states=SimpleNamespace(list=onboarding_list),
        data_connectors=SimpleNamespace(list=lambda rg, wn: connectors or []),
        alert_rules=SimpleNamespace(list=lambda rg, wn: alert_rules or []),
        automation_rules=SimpleNamespace(list=lambda rg, wn: automation_rules or []),
    )


def _log_analytics(workspaces):
    return SimpleNamespace(workspaces=SimpleNamespace(list=lambda: workspaces))


def _connector(kind: str, enabled: bool = True):
    data_types = SimpleNamespace(alerts=SimpleNamespace(state="Enabled" if enabled else "Disabled"), logs=None)
    return SimpleNamespace(kind=kind, data_types=data_types)


def _alert_rule(display_name: str, severity: str, enabled: bool = True):
    return SimpleNamespace(display_name=display_name, severity=severity, enabled=enabled)


# ── AZ-SECOPS-008: Sentinel data connector health ───────────────────────────


def test_secops_008_no_log_analytics_workspaces_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    collector = make_collector(log_analytics_client=_log_analytics([]))
    stub_collector(monkeypatch, az_secops_008, collector)
    assert az_secops_008.scan(_client(), _SUB) == []


def test_secops_008_no_sentinel_onboarded_workspaces_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    ws = workspace(name="ws1")
    collector = make_collector(
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(onboarded=False),
    )
    stub_collector(monkeypatch, az_secops_008, collector)
    assert az_secops_008.scan(_client(), _SUB) == []


def test_secops_008_required_connector_present_and_enabled_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_sentinel_connectors=["AzureActiveDirectory"])
    ws = workspace(name="ws1")
    connectors = [_connector("AzureActiveDirectory", enabled=True)]
    collector = make_collector(
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(onboarded=True, connectors=connectors),
    )
    stub_collector(monkeypatch, az_secops_008, collector)
    assert az_secops_008.scan(_client(), _SUB) == []


def test_secops_008_required_connector_missing_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_sentinel_connectors=["AzureActiveDirectory"])
    ws = workspace(name="ws1")
    collector = make_collector(
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(onboarded=True, connectors=[]),
    )
    stub_collector(monkeypatch, az_secops_008, collector)
    findings = az_secops_008.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["connector_state"] == "missing"


def test_secops_008_required_connector_disconnected_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_sentinel_connectors=["AzureActiveDirectory"])
    ws = workspace(name="ws1")
    connectors = [_connector("AzureActiveDirectory", enabled=False)]
    collector = make_collector(
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(onboarded=True, connectors=connectors),
    )
    stub_collector(monkeypatch, az_secops_008, collector)
    findings = az_secops_008.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["connector_state"] == "disconnected"


def test_secops_008_empty_required_connectors_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_sentinel_connectors=[])
    collector = make_collector(log_analytics_client=_log_analytics([]))
    stub_collector(monkeypatch, az_secops_008, collector)
    assert az_secops_008.scan(_client(), _SUB) == []


def test_secops_008_workspace_discovery_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_sentinel_connectors=["AzureActiveDirectory"])

    def fail():
        raise RuntimeError("boom")

    collector = make_collector(log_analytics_client=SimpleNamespace(workspaces=SimpleNamespace(list=fail)))
    stub_collector(monkeypatch, az_secops_008, collector)
    assert az_secops_008.scan(_client(), _SUB) == []


def test_secops_008_onboarding_permission_failure_is_unknown_not_fail(monkeypatch, tmp_path):
    """A workspace whose Sentinel onboarding check 403s must be UNKNOWN, not silently skipped as compliant."""
    set_policy_env(monkeypatch, tmp_path, required_sentinel_connectors=["AzureActiveDirectory"])
    ws = workspace(name="ws1")
    collector = make_collector(
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(raise_onboarding=True),
    )
    stub_collector(monkeypatch, az_secops_008, collector)
    # Only workspace fails and none succeed -> whole collection reported FAILED -> UNKNOWN -> no findings.
    assert az_secops_008.scan(_client(), _SUB) == []


# ── AZ-SECOPS-009: Sentinel high-severity analytics coverage ────────────────


def test_secops_009_covered_by_enabled_high_severity_rule_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_high_severity_analytics=["privileged-role-change"])
    ws = workspace(name="ws1")
    rules = [_alert_rule("Privileged Role Change Detected", "High", enabled=True)]
    collector = make_collector(
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(onboarded=True, alert_rules=rules),
    )
    stub_collector(monkeypatch, az_secops_009, collector)
    assert az_secops_009.scan(_client(), _SUB) == []


def test_secops_009_disabled_rule_does_not_count_as_coverage(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_high_severity_analytics=["privileged-role-change"])
    ws = workspace(name="ws1")
    rules = [_alert_rule("Privileged Role Change Detected", "High", enabled=False)]
    collector = make_collector(
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(onboarded=True, alert_rules=rules),
    )
    stub_collector(monkeypatch, az_secops_009, collector)
    findings = az_secops_009.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["use_case"] == "privileged-role-change"


def test_secops_009_low_severity_rule_does_not_count_as_coverage(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_high_severity_analytics=["privileged-role-change"])
    ws = workspace(name="ws1")
    rules = [_alert_rule("Privileged Role Change Detected", "Low", enabled=True)]
    collector = make_collector(
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(onboarded=True, alert_rules=rules),
    )
    stub_collector(monkeypatch, az_secops_009, collector)
    findings = az_secops_009.scan(_client(), _SUB)
    assert len(findings) == 1


def test_secops_009_no_onboarded_workspaces_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_high_severity_analytics=["privileged-role-change"])
    collector = make_collector(log_analytics_client=_log_analytics([]))
    stub_collector(monkeypatch, az_secops_009, collector)
    assert az_secops_009.scan(_client(), _SUB) == []


def test_secops_009_empty_required_analytics_is_not_applicable(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_high_severity_analytics=[])
    collector = make_collector(log_analytics_client=_log_analytics([]))
    stub_collector(monkeypatch, az_secops_009, collector)
    assert az_secops_009.scan(_client(), _SUB) == []


def test_secops_009_alert_rules_collection_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path, required_high_severity_analytics=["privileged-role-change"])
    ws = workspace(name="ws1")

    def fail(rg, wn):
        raise RuntimeError("boom")

    sentinel = SimpleNamespace(
        sentinel_onboarding_states=SimpleNamespace(list=lambda rg, wn: _onboarding_states_list(1)),
        alert_rules=SimpleNamespace(list=fail),
        data_connectors=SimpleNamespace(list=lambda rg, wn: []),
        automation_rules=SimpleNamespace(list=lambda rg, wn: []),
    )
    collector = make_collector(log_analytics_client=_log_analytics([ws]), sentinel_client_factory=lambda rg: sentinel)
    stub_collector(monkeypatch, az_secops_009, collector)
    assert az_secops_009.scan(_client(), _SUB) == []


# ── AZ-SECOPS-010: incident-response destination ────────────────────────────


def _action_group(enabled=True, email_receivers=None):
    return SimpleNamespace(
        enabled=enabled,
        email_receivers=email_receivers or [],
        sms_receivers=[],
        webhook_receivers=[],
        itsm_receivers=[],
        azure_app_push_receivers=[],
        automation_runbook_receivers=[],
        voice_receivers=[],
        logic_app_receivers=[],
        azure_function_receivers=[],
        event_hub_receivers=[],
    )


def test_secops_010_monitored_action_group_is_compliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(
        action_groups=SimpleNamespace(
            list_by_subscription_id=lambda: [_action_group(enabled=True, email_receivers=[SimpleNamespace()])]
        )
    )
    collector = make_collector(monitor_client=monitor)
    stub_collector(monkeypatch, az_secops_010, collector)
    assert az_secops_010.scan(_client(), _SUB) == []


def test_secops_010_action_group_with_no_receivers_is_not_monitored(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(
        action_groups=SimpleNamespace(list_by_subscription_id=lambda: [_action_group(enabled=True)])
    )
    collector = make_collector(monitor_client=monitor, log_analytics_client=_log_analytics([]))
    stub_collector(monkeypatch, az_secops_010, collector)
    findings = az_secops_010.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["destination"] == "none-monitored"


def test_secops_010_disabled_action_group_is_not_monitored(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(
        action_groups=SimpleNamespace(
            list_by_subscription_id=lambda: [_action_group(enabled=False, email_receivers=[SimpleNamespace()])]
        )
    )
    collector = make_collector(monitor_client=monitor, log_analytics_client=_log_analytics([]))
    stub_collector(monkeypatch, az_secops_010, collector)
    findings = az_secops_010.scan(_client(), _SUB)
    assert len(findings) == 1


def test_secops_010_no_action_group_but_sentinel_automation_rule_is_compliant(monkeypatch, tmp_path):
    """A Sentinel automation rule routing incidents is an accepted alternative destination."""
    set_policy_env(monkeypatch, tmp_path)
    ws = workspace(name="ws1")
    monitor = SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=lambda: []))
    automation_rules = [SimpleNamespace(display_name="route-to-playbook")]
    collector = make_collector(
        monitor_client=monitor,
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(onboarded=True, automation_rules=automation_rules),
    )
    stub_collector(monkeypatch, az_secops_010, collector)
    assert az_secops_010.scan(_client(), _SUB) == []


def test_secops_010_no_action_group_and_no_automation_rule_is_noncompliant(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)
    ws = workspace(name="ws1")
    monitor = SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=lambda: []))
    collector = make_collector(
        monitor_client=monitor,
        log_analytics_client=_log_analytics([ws]),
        sentinel_client_factory=lambda rg: _sentinel_client(onboarded=True, automation_rules=[]),
    )
    stub_collector(monkeypatch, az_secops_010, collector)
    findings = az_secops_010.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["sentinel_automation_rule_coverage"] is False


def test_secops_010_empty_action_groups_inventory_is_noncompliant_not_unknown(monkeypatch, tmp_path):
    """An empty (but successfully collected) action-group inventory is real evidence of absence."""
    set_policy_env(monkeypatch, tmp_path)
    monitor = SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=lambda: []))
    collector = make_collector(monitor_client=monitor, log_analytics_client=_log_analytics([]))
    stub_collector(monkeypatch, az_secops_010, collector)
    findings = az_secops_010.scan(_client(), _SUB)
    assert len(findings) == 1
    assert findings[0]["metadata"]["action_groups_found"] == 0


def test_secops_010_action_groups_api_failure_is_unknown(monkeypatch, tmp_path):
    set_policy_env(monkeypatch, tmp_path)

    def fail():
        raise PermissionError("denied")

    monitor = SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=fail))
    collector = make_collector(monitor_client=monitor)
    stub_collector(monkeypatch, az_secops_010, collector)
    assert az_secops_010.scan(_client(), _SUB) == []


def test_secops_010_onboarding_discovery_partial_is_unknown_not_fail(monkeypatch, tmp_path):
    """One workspace's Sentinel onboarding check fails; the other is confirmed onboarded with
    no automation rule. The failed workspace might have had the routing rule, so this must be
    UNKNOWN, not a confident FAIL."""
    set_policy_env(monkeypatch, tmp_path)
    ws_ok = workspace(name="ws-ok", resource_group="rg-ok")
    ws_denied = workspace(name="ws-denied", resource_group="rg-denied")
    monitor = SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=lambda: []))

    def sentinel_factory(rg):
        if rg == "rg-denied":
            return _sentinel_client(raise_onboarding=True)
        return _sentinel_client(onboarded=True, automation_rules=[])

    collector = make_collector(
        monitor_client=monitor,
        log_analytics_client=_log_analytics([ws_ok, ws_denied]),
        sentinel_client_factory=sentinel_factory,
    )
    stub_collector(monkeypatch, az_secops_010, collector)
    assert az_secops_010.scan(_client(), _SUB) == []


def test_secops_010_automation_rules_partial_is_unknown_not_fail(monkeypatch, tmp_path):
    """Both workspaces are confirmed Sentinel-onboarded, but the automation-rules collection
    fails for one of them. The reachable workspace has no automation rule, but the unreachable
    one might have had the routing rule, so this must be UNKNOWN, not a confident FAIL."""
    set_policy_env(monkeypatch, tmp_path)
    ws_ok = workspace(name="ws-ok", resource_group="rg-ok")
    ws_broken = workspace(name="ws-broken", resource_group="rg-broken")
    monitor = SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=lambda: []))

    def automation_rules_list(rg, wn):
        if rg == "rg-broken":
            raise RuntimeError("boom")
        return []

    def sentinel_factory(rg):
        return SimpleNamespace(
            sentinel_onboarding_states=SimpleNamespace(list=lambda rg, wn: _onboarding_states_list(1)),
            data_connectors=SimpleNamespace(list=lambda rg, wn: []),
            alert_rules=SimpleNamespace(list=lambda rg, wn: []),
            automation_rules=SimpleNamespace(list=automation_rules_list),
        )

    collector = make_collector(
        monitor_client=monitor,
        log_analytics_client=_log_analytics([ws_ok, ws_broken]),
        sentinel_client_factory=sentinel_factory,
    )
    stub_collector(monkeypatch, az_secops_010, collector)
    assert az_secops_010.scan(_client(), _SUB) == []


def test_secops_010_automation_rules_partial_but_coverage_found_is_compliant(monkeypatch, tmp_path):
    """Automation-rules collection fails for one workspace, but the reachable workspace already
    has a routing rule. Coverage is real evidence and should short-circuit before the incomplete
    evidence from the other workspace is even considered."""
    set_policy_env(monkeypatch, tmp_path)
    ws_covered = workspace(name="ws-covered", resource_group="rg-covered")
    ws_broken = workspace(name="ws-broken", resource_group="rg-broken")
    monitor = SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=lambda: []))
    automation_rules = [SimpleNamespace(display_name="route-to-playbook")]

    def automation_rules_list(rg, wn):
        if rg == "rg-broken":
            raise RuntimeError("boom")
        return automation_rules

    def sentinel_factory(rg):
        return SimpleNamespace(
            sentinel_onboarding_states=SimpleNamespace(list=lambda rg, wn: _onboarding_states_list(1)),
            data_connectors=SimpleNamespace(list=lambda rg, wn: []),
            alert_rules=SimpleNamespace(list=lambda rg, wn: []),
            automation_rules=SimpleNamespace(list=automation_rules_list),
        )

    collector = make_collector(
        monitor_client=monitor,
        log_analytics_client=_log_analytics([ws_covered, ws_broken]),
        sentinel_client_factory=sentinel_factory,
    )
    stub_collector(monkeypatch, az_secops_010, collector)
    assert az_secops_010.scan(_client(), _SUB) == []
