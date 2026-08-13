"""Read-only collection foundation for enterprise security-operations controls."""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Generic, Mapping, Sequence, TypeVar

from azure.mgmt.monitor import MonitorManagementClient

T = TypeVar("T")


class CollectionStatus(str, Enum):
    """Whether a collector produced authoritative evidence."""

    COMPLETE = "COMPLETE"
    FAILED = "FAILED"


@dataclass(frozen=True)
class CollectionResult(Generic[T]):
    """Explicit collector result; an API failure is never an empty inventory."""

    status: CollectionStatus
    items: tuple[T, ...]
    source: str
    error_code: str | None = None

    @classmethod
    def complete(cls, items: Sequence[T], source: str) -> CollectionResult[T]:
        return cls(CollectionStatus.COMPLETE, tuple(items), source)

    @classmethod
    def failed(cls, source: str, error_code: str = "COLLECTION_FAILED") -> CollectionResult[T]:
        return cls(CollectionStatus.FAILED, (), source, error_code)


@dataclass(frozen=True)
class SecurityOperationsPolicy:
    """Organisation-owned inputs required before evaluating issue #262 rules."""

    critical_resource_types: frozenset[str]
    approved_destination_ids: frozenset[str]
    required_activity_categories: frozenset[str]
    minimum_retention_days: int
    required_defender_plans: frozenset[str]
    defender_recommendation_sla_days: int
    required_sentinel_connectors: frozenset[str]
    required_high_severity_analytics: tuple[str, ...]
    approved_exclusions: frozenset[str]


_POLICY_FIELDS = {
    "critical_resource_types",
    "approved_destination_ids",
    "required_activity_categories",
    "minimum_retention_days",
    "required_defender_plans",
    "defender_recommendation_sla_days",
    "required_sentinel_connectors",
    "required_high_severity_analytics",
    "approved_exclusions",
}


def load_security_operations_policy(path: str | Path) -> SecurityOperationsPolicy:
    """Load a strict policy file without silently inventing enterprise defaults."""
    with Path(path).open(encoding="utf-8") as handle:
        raw = json.load(handle)
    if not isinstance(raw, dict) or set(raw) != _POLICY_FIELDS:
        raise ValueError("security-operations policy has missing or unsupported fields")

    list_fields = _POLICY_FIELDS - {"minimum_retention_days", "defender_recommendation_sla_days"}
    for field in list_fields:
        values = raw[field]
        if not isinstance(values, list) or any(not isinstance(value, str) or not value.strip() for value in values):
            raise ValueError(f"{field} must be a list of non-empty strings")
    for field in ("minimum_retention_days", "defender_recommendation_sla_days"):
        if not isinstance(raw[field], int) or isinstance(raw[field], bool) or raw[field] <= 0:
            raise ValueError(f"{field} must be a positive integer")

    normalised = {field: frozenset(value.strip().lower() for value in raw[field]) for field in list_fields}
    return SecurityOperationsPolicy(
        critical_resource_types=normalised["critical_resource_types"],
        approved_destination_ids=normalised["approved_destination_ids"],
        required_activity_categories=normalised["required_activity_categories"],
        minimum_retention_days=raw["minimum_retention_days"],
        required_defender_plans=normalised["required_defender_plans"],
        defender_recommendation_sla_days=raw["defender_recommendation_sla_days"],
        required_sentinel_connectors=normalised["required_sentinel_connectors"],
        required_high_severity_analytics=tuple(value.strip() for value in raw["required_high_severity_analytics"]),
        approved_exclusions=normalised["approved_exclusions"],
    )


class SecurityOperationsCollector:
    """Collect Azure Monitor configuration without reading log content."""

    def __init__(
        self,
        credential: Any,
        subscription_id: str,
        *,
        monitor_client: Any | None = None,
        resource_inventory: Callable[[], Sequence[Any]] | None = None,
    ) -> None:
        self.monitor = monitor_client or MonitorManagementClient(credential, subscription_id)
        self.resource_inventory = resource_inventory

    def subscription_diagnostic_settings(self) -> CollectionResult[Any]:
        source = "Microsoft.Insights/subscriptionDiagnosticSettings"
        try:
            return CollectionResult.complete(list(self.monitor.subscription_diagnostic_settings.list()), source)
        except Exception:
            return CollectionResult.failed(source)

    def resource_diagnostic_settings(
        self, resource_ids: Sequence[str]
    ) -> CollectionResult[Mapping[str, tuple[Any, ...]]]:
        source = "Microsoft.Insights/diagnosticSettings"
        collected: dict[str, tuple[Any, ...]] = {}
        try:
            for resource_id in resource_ids:
                if not isinstance(resource_id, str) or not resource_id.strip():
                    raise ValueError("resource IDs must be non-empty strings")
                collected[resource_id] = tuple(self.monitor.diagnostic_settings.list(resource_id))
            return CollectionResult.complete((collected,), source)
        except Exception:
            return CollectionResult.failed(source)

    def critical_resource_ids(self, policy: SecurityOperationsPolicy) -> CollectionResult[str]:
        source = "Azure resource inventory"
        if self.resource_inventory is None:
            return CollectionResult.failed(source, "INVENTORY_NOT_CONFIGURED")
        try:
            resources = self.resource_inventory()
            ids = []
            for resource in resources:
                resource_id = str(getattr(resource, "id", "") or "").strip()
                resource_type = str(getattr(resource, "type", "") or "").strip().lower()
                if resource_id and resource_type in policy.critical_resource_types:
                    ids.append(resource_id)
            return CollectionResult.complete(ids, source)
        except Exception:
            return CollectionResult.failed(source)
