"""Shared helpers for App Registration and managed-identity rules."""

from typing import Any, Dict, Mapping


def application_identity(application: Mapping[str, Any]) -> tuple[str, str]:
    """Return the Graph application object ID and a safe display name."""
    object_id = str(application.get("id", "") or "")
    display_name = str(application.get("displayName") or application.get("appId") or object_id)
    return object_id, display_name


def application_finding(
    application: Mapping[str, Any],
    *,
    rule_id: str,
    rule_name: str,
    severity: str,
    description: str,
    remediation: str,
    playbook: str,
    frameworks: Mapping[str, str],
    metadata: Mapping[str, Any],
) -> Dict[str, Any]:
    """Build the repository-standard finding for a Microsoft Graph application."""
    object_id, display_name = application_identity(application)
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "category": "Identity",
        "resource_id": f"/applications/{object_id}",
        "resource_name": display_name,
        "resource_type": "Microsoft.Graph/applications",
        "description": description,
        "remediation": remediation,
        "playbook": playbook,
        "frameworks": dict(frameworks),
        "metadata": dict(metadata),
    }
