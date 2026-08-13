"""Shared test helpers for the AZ-SECOPS-001..010 rule test suite."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional

from scanner.security_operations import SecurityOperationsCollector

DEFAULT_POLICY_PAYLOAD: Dict[str, Any] = {
    "critical_resource_types": ["Microsoft.KeyVault/vaults", "Microsoft.Sql/servers"],
    "approved_destination_ids": [
        "/subscriptions/sub/resourcegroups/security/providers/microsoft.operationalinsights/workspaces/central-security"
    ],
    "required_activity_categories": ["Administrative", "Security", "Policy", "ServiceHealth"],
    "minimum_retention_days": 90,
    "required_defender_plans": ["VirtualMachines", "StorageAccounts"],
    "defender_recommendation_sla_days": 30,
    "required_sentinel_connectors": ["AzureActiveDirectory", "AzureSecurityCenter"],
    "required_high_severity_analytics": ["privileged-role-change", "credential-abuse"],
    "approved_exclusions": [],
}


def write_policy(tmp_path: Path, **overrides: Any) -> Path:
    """Write a valid security-operations policy JSON file and return its path."""
    payload = json.loads(json.dumps(DEFAULT_POLICY_PAYLOAD))
    payload.update(overrides)
    path = tmp_path / "secops-policy.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def set_policy_env(monkeypatch: Any, tmp_path: Path, **overrides: Any) -> Path:
    """Write a policy file and point OPENSHIELD_SECURITY_OPERATIONS_POLICY at it."""
    path = write_policy(tmp_path, **overrides)
    monkeypatch.setenv("OPENSHIELD_SECURITY_OPERATIONS_POLICY", str(path))
    return path


def stub_collector(monkeypatch: Any, module: Any, collector: SecurityOperationsCollector) -> None:
    """Patch a rule module's build_collector() to return a preconfigured collector."""
    monkeypatch.setattr(module, "build_collector", lambda azure_client, subscription_id: collector)


def make_collector(**overrides: Any) -> SecurityOperationsCollector:
    """Build a SecurityOperationsCollector with any combination of test-double clients."""
    return SecurityOperationsCollector(
        credential=None,
        subscription_id="00000000-0000-0000-0000-000000000001",
        monitor_client=overrides.get("monitor_client", SimpleNamespace()),
        resource_inventory=overrides.get("resource_inventory"),
        security_client=overrides.get("security_client"),
        log_analytics_client=overrides.get("log_analytics_client"),
        sentinel_client_factory=overrides.get("sentinel_client_factory"),
    )


def diagnostic_setting(
    *,
    workspace_id: Optional[str] = None,
    storage_account_id: Optional[str] = None,
    event_hub_authorization_rule_id: Optional[str] = None,
    logs: Optional[list] = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        workspace_id=workspace_id,
        storage_account_id=storage_account_id,
        event_hub_authorization_rule_id=event_hub_authorization_rule_id,
        logs=logs or [],
    )


def log_setting(
    *,
    category: Optional[str] = None,
    category_group: Optional[str] = None,
    enabled: bool = True,
    retention_policy: Optional[SimpleNamespace] = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        category=category,
        category_group=category_group,
        enabled=enabled,
        retention_policy=retention_policy,
    )


def retention_policy(*, enabled: bool, days: int) -> SimpleNamespace:
    return SimpleNamespace(enabled=enabled, days=days)


def workspace(*, name: str, resource_group: str = "rg-sec") -> SimpleNamespace:
    return SimpleNamespace(
        id=(
            f"/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/{resource_group}"
            f"/providers/Microsoft.OperationalInsights/workspaces/{name}"
        ),
        name=name,
    )
