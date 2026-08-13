"""Tests for issue #262 policy and read-only collection contracts."""

import json
from types import SimpleNamespace

import pytest

from scanner.security_operations import (
    CollectionStatus,
    SecurityOperationsCollector,
    load_security_operations_policy,
)


def _policy(tmp_path, **overrides):
    payload = {
        "critical_resource_types": ["Microsoft.KeyVault/vaults"],
        "approved_destination_ids": ["/subscriptions/sub/workspaces/security"],
        "required_activity_categories": ["Administrative", "Security"],
        "minimum_retention_days": 90,
        "required_defender_plans": ["VirtualMachines"],
        "defender_recommendation_sla_days": 30,
        "required_sentinel_connectors": ["AzureActiveDirectory"],
        "required_high_severity_analytics": ["privileged-role-change"],
        "approved_exclusions": [],
    }
    payload.update(overrides)
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_policy_is_strict_and_normalised(tmp_path):
    policy = load_security_operations_policy(_policy(tmp_path))
    assert policy.critical_resource_types == {"microsoft.keyvault/vaults"}
    assert policy.minimum_retention_days == 90


@pytest.mark.parametrize(
    "override",
    [
        {"minimum_retention_days": 0},
        {"required_activity_categories": "Security"},
        {"approved_exclusions": [""]},
    ],
)
def test_policy_rejects_unsafe_shapes(tmp_path, override):
    with pytest.raises(ValueError):
        load_security_operations_policy(_policy(tmp_path, **override))


def test_subscription_diagnostics_distinguish_empty_success_from_failure():
    complete_monitor = SimpleNamespace(
        subscription_diagnostic_settings=SimpleNamespace(list=lambda: []),
    )
    complete = SecurityOperationsCollector(None, "sub", monitor_client=complete_monitor)
    assert complete.subscription_diagnostic_settings().status is CollectionStatus.COMPLETE
    assert complete.subscription_diagnostic_settings().items == ()

    def fail():
        raise PermissionError("secret response must not escape")

    failed_monitor = SimpleNamespace(subscription_diagnostic_settings=SimpleNamespace(list=fail))
    failed = SecurityOperationsCollector(None, "sub", monitor_client=failed_monitor)
    result = failed.subscription_diagnostic_settings()
    assert result.status is CollectionStatus.FAILED
    assert result.error_code == "COLLECTION_FAILED"


def test_resource_diagnostics_are_read_per_resource_and_fail_closed():
    calls = []
    monitor = SimpleNamespace(
        diagnostic_settings=SimpleNamespace(list=lambda resource_id: calls.append(resource_id) or [resource_id]),
    )
    collector = SecurityOperationsCollector(None, "sub", monitor_client=monitor)
    result = collector.resource_diagnostic_settings(["/resource/one", "/resource/two"])
    assert result.status is CollectionStatus.COMPLETE
    assert calls == ["/resource/one", "/resource/two"]
    assert result.items[0]["/resource/one"] == ("/resource/one",)


def test_critical_resource_inventory_uses_policy_and_preserves_failure(tmp_path):
    policy = load_security_operations_policy(_policy(tmp_path))
    resources = [
        SimpleNamespace(id="/critical", type="Microsoft.KeyVault/vaults"),
        SimpleNamespace(id="/other", type="Microsoft.Compute/virtualMachines"),
    ]
    collector = SecurityOperationsCollector(None, "sub", monitor_client=object(), resource_inventory=lambda: resources)
    result = collector.critical_resource_ids(policy)
    assert result.status is CollectionStatus.COMPLETE
    assert result.items == ("/critical",)

    failed = SecurityOperationsCollector(
        None,
        "sub",
        monitor_client=object(),
        resource_inventory=lambda: (_ for _ in ()).throw(RuntimeError("boom")),
    )
    assert failed.critical_resource_ids(policy).status is CollectionStatus.FAILED
