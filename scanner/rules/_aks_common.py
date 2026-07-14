"""Shared helpers for Azure Kubernetes Service rule modules."""

from typing import Any, Dict, Mapping

_MISSING = object()


def cluster_property(cluster: Any, name: str, default: Any = None) -> Any:
    """Read an AKS property across both flattened and nested SDK models."""
    value = getattr(cluster, name, _MISSING)
    if value is not _MISSING:
        return value

    properties = getattr(cluster, "properties", None)
    if properties is None:
        return default
    return getattr(properties, name, default)


def resource_identity(cluster: Any) -> tuple[str, str]:
    """Return a validated AKS resource ID and display name."""
    resource_id = getattr(cluster, "id", "") or ""
    resource_name = getattr(cluster, "name", "") or ""
    return resource_id, resource_name


def finding(
    cluster: Any,
    *,
    rule_id: str,
    rule_name: str,
    severity: str,
    category: str,
    description: str,
    remediation: str,
    playbook: str,
    frameworks: Mapping[str, str],
    metadata: Mapping[str, Any],
) -> Dict[str, Any]:
    """Build the repository-standard finding payload for an AKS cluster."""
    resource_id, resource_name = resource_identity(cluster)
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "category": category,
        "resource_id": resource_id,
        "resource_name": resource_name,
        "resource_type": "Microsoft.ContainerService/managedClusters",
        "description": description,
        "remediation": remediation,
        "playbook": playbook,
        "frameworks": dict(frameworks),
        "metadata": dict(metadata),
    }
