"""Tests for the issue #262 collector extensions: Defender pricing/assessments and
Sentinel auto-discovery (controls 6-10). Complements test_security_operations_foundation.py,
which covers the original subscription/resource diagnostic-settings collectors and must not change."""

from types import SimpleNamespace

from scanner.security_operations import CollectionStatus, SecurityOperationsCollector, workspace_scope_key


def _workspace(name: str, rg: str = "rg-sec") -> SimpleNamespace:
    return SimpleNamespace(
        id=f"/subscriptions/sub/resourceGroups/{rg}/providers/Microsoft.OperationalInsights/workspaces/{name}",
        name=name,
    )


# ── Defender pricing / assessments ──────────────────────────────────────────


def test_defender_pricings_unwraps_pricing_list_value():
    security = SimpleNamespace(
        pricings=SimpleNamespace(
            list=lambda scope_id, **kw: SimpleNamespace(value=[SimpleNamespace(name="VirtualMachines")])
        )
    )
    collector = SecurityOperationsCollector(None, "sub", monitor_client=object(), security_client=security)
    result = collector.defender_pricings()
    assert result.status is CollectionStatus.COMPLETE
    assert result.items[0].name == "VirtualMachines"


def test_defender_pricings_failure_is_failed():
    def fail(scope_id, **kw):
        raise PermissionError("denied")

    security = SimpleNamespace(pricings=SimpleNamespace(list=fail))
    collector = SecurityOperationsCollector(None, "sub", monitor_client=object(), security_client=security)
    assert collector.defender_pricings().status is CollectionStatus.FAILED


def test_defender_assessments_empty_success_is_complete():
    security = SimpleNamespace(assessments=SimpleNamespace(list=lambda scope: []))
    collector = SecurityOperationsCollector(None, "sub", monitor_client=object(), security_client=security)
    result = collector.defender_assessments()
    assert result.status is CollectionStatus.COMPLETE
    assert result.items == ()


def test_defender_assessments_failure_is_failed():
    def fail(scope):
        raise RuntimeError("boom")

    security = SimpleNamespace(assessments=SimpleNamespace(list=fail))
    collector = SecurityOperationsCollector(None, "sub", monitor_client=object(), security_client=security)
    assert collector.defender_assessments().status is CollectionStatus.FAILED


# ── Sentinel auto-discovery ──────────────────────────────────────────────────


def test_log_analytics_workspaces_complete_and_failed():
    log_analytics = SimpleNamespace(workspaces=SimpleNamespace(list=lambda: [_workspace("ws1")]))
    collector = SecurityOperationsCollector(None, "sub", monitor_client=object(), log_analytics_client=log_analytics)
    result = collector.log_analytics_workspaces()
    assert result.status is CollectionStatus.COMPLETE
    assert result.items[0].name == "ws1"

    def fail():
        raise RuntimeError("boom")

    failing_la = SimpleNamespace(workspaces=SimpleNamespace(list=fail))
    failing_collector = SecurityOperationsCollector(
        None, "sub", monitor_client=object(), log_analytics_client=failing_la
    )
    assert failing_collector.log_analytics_workspaces().status is CollectionStatus.FAILED


def test_workspace_scope_key_extracts_resource_group_and_name():
    ws = _workspace("ws1", rg="rg-sec")
    assert workspace_scope_key(ws) == "rg-sec/ws1"


def test_sentinel_onboarded_workspaces_filters_to_onboarded_only():
    ws1 = _workspace("ws-onboarded")
    ws2 = _workspace("ws-not-onboarded")
    log_analytics = SimpleNamespace(workspaces=SimpleNamespace(list=lambda: [ws1, ws2]))

    def factory(rg):
        def list_states(resource_group, workspace_name):
            if workspace_name == "ws-onboarded":
                return SimpleNamespace(value=[SimpleNamespace(name="state")])
            return SimpleNamespace(value=[])

        return SimpleNamespace(sentinel_onboarding_states=SimpleNamespace(list=list_states))

    collector = SecurityOperationsCollector(
        None, "sub", monitor_client=object(), log_analytics_client=log_analytics, sentinel_client_factory=factory
    )
    result = collector.sentinel_onboarded_workspaces()
    assert result.status is CollectionStatus.COMPLETE
    assert [w.name for w in result.items] == ["ws-onboarded"]


def test_sentinel_onboarded_workspaces_partial_when_some_checks_fail():
    ws1 = _workspace("ws-ok")
    ws2 = _workspace("ws-denied")
    log_analytics = SimpleNamespace(workspaces=SimpleNamespace(list=lambda: [ws1, ws2]))

    def factory(rg):
        def list_states(resource_group, workspace_name):
            if workspace_name == "ws-denied":
                raise PermissionError("denied")
            return SimpleNamespace(value=[SimpleNamespace(name="state")])

        return SimpleNamespace(sentinel_onboarding_states=SimpleNamespace(list=list_states))

    collector = SecurityOperationsCollector(
        None, "sub", monitor_client=object(), log_analytics_client=log_analytics, sentinel_client_factory=factory
    )
    result = collector.sentinel_onboarded_workspaces()
    assert result.status is CollectionStatus.PARTIAL
    assert [w.name for w in result.items] == ["ws-ok"]
    assert "rg-sec/ws-denied" in result.failed_scopes


def test_sentinel_onboarded_workspaces_failed_when_all_checks_fail():
    ws1 = _workspace("ws-denied-1")
    log_analytics = SimpleNamespace(workspaces=SimpleNamespace(list=lambda: [ws1]))

    def factory(rg):
        def list_states(resource_group, workspace_name):
            raise PermissionError("denied")

        return SimpleNamespace(sentinel_onboarding_states=SimpleNamespace(list=list_states))

    collector = SecurityOperationsCollector(
        None, "sub", monitor_client=object(), log_analytics_client=log_analytics, sentinel_client_factory=factory
    )
    result = collector.sentinel_onboarded_workspaces()
    assert result.status is CollectionStatus.FAILED


def test_sentinel_onboarded_workspaces_propagates_log_analytics_failure():
    def fail():
        raise RuntimeError("boom")

    log_analytics = SimpleNamespace(workspaces=SimpleNamespace(list=fail))
    collector = SecurityOperationsCollector(None, "sub", monitor_client=object(), log_analytics_client=log_analytics)
    assert collector.sentinel_onboarded_workspaces().status is CollectionStatus.FAILED


def test_sentinel_data_connectors_collects_per_workspace():
    ws1 = _workspace("ws1")
    connector = SimpleNamespace(kind="AzureActiveDirectory")

    def factory(rg):
        return SimpleNamespace(data_connectors=SimpleNamespace(list=lambda rg_, wn: [connector]))

    collector = SecurityOperationsCollector(None, "sub", monitor_client=object(), sentinel_client_factory=factory)
    result = collector.sentinel_data_connectors([ws1])
    assert result.status is CollectionStatus.COMPLETE
    assert result.items[0]["rg-sec/ws1"][0].kind == "AzureActiveDirectory"


def test_sentinel_data_connectors_partial_on_mixed_failure():
    ws1 = _workspace("ws-ok")
    ws2 = _workspace("ws-fail")

    def factory(rg):
        def list_connectors(rg_, wn):
            if wn == "ws-fail":
                raise RuntimeError("boom")
            return [SimpleNamespace(kind="AzureActiveDirectory")]

        return SimpleNamespace(data_connectors=SimpleNamespace(list=list_connectors))

    collector = SecurityOperationsCollector(None, "sub", monitor_client=object(), sentinel_client_factory=factory)
    result = collector.sentinel_data_connectors([ws1, ws2])
    assert result.status is CollectionStatus.PARTIAL
    assert "rg-sec/ws-fail" in result.failed_scopes


def test_action_groups_complete_and_failed():
    monitor = SimpleNamespace(
        action_groups=SimpleNamespace(list_by_subscription_id=lambda: [SimpleNamespace(enabled=True)])
    )
    collector = SecurityOperationsCollector(None, "sub", monitor_client=monitor)
    result = collector.action_groups()
    assert result.status is CollectionStatus.COMPLETE
    assert len(result.items) == 1

    def fail():
        raise PermissionError("secret must not leak")

    failing_monitor = SimpleNamespace(action_groups=SimpleNamespace(list_by_subscription_id=fail))
    failing_collector = SecurityOperationsCollector(None, "sub", monitor_client=failing_monitor)
    assert failing_collector.action_groups().status is CollectionStatus.FAILED
