"""Shared, secret-safe helpers for the issue #262 security-operations rules (AZ-SECOPS-001..010).

Reconciling the 4-state PASS/FAIL/UNKNOWN/NOT_APPLICABLE model required by
issue #262 with the existing findings-list-only ``scan()`` contract:

``scanner/engine.py`` treats *presence of a finding in the returned list* as
the only signal of non-compliance (it feeds the list straight into a
severity-weighted score). It has no field or side channel for a rule to say
"this resource is compliant", "this is out of scope", or "I could not tell".
Two existing rule families in this repo already answer this exact question:
``scanner/rules/az_dl_001.py``/``az_dl_002.py`` (via
``scanner/rules/_data_link_common.py``) and ``az_kv_003.py``. Both follow the
same pattern and this module continues it rather than inventing a third,
incompatible convention:

  * PASS is an empty list. No finding is emitted for a compliant resource.
  * NOT_APPLICABLE is an empty list plus an ``INFO``-level log line. Nothing
    in scope means nothing to report.
  * UNKNOWN is an empty list plus a ``WARNING``-level log line. A collector
    failure, an inaccessible permission, or a policy that cannot be loaded
    must never be silently promoted to a compliance claim, so it is treated
    the same as "no evidence of a violation" for scoring purposes and is
    never converted into a FAIL.
  * FAIL is the only outcome that produces a finding dict, and only when
    there is positive evidence of a missing or unsafe control.

This satisfies "Return NOT_APPLICABLE / UNKNOWN" and "Return FAIL only with
positive evidence" without changing what ``engine.py`` does with the return
value of ``scan()``. The richer per-finding metadata the issue also asks for
(scope, category, destination, retention, ownership, evidence/timestamp,
remediation, permissions, severity, confidence, and an UNKNOWN reason) is
carried on every FAIL finding's ``metadata`` dict so a UI or export can still
show "why" even though UNKNOWN/NOT_APPLICABLE outcomes themselves are not
individually addressable dict rows. This is a real, structural limitation of
the current engine contract for these two states — flagged here rather than
worked around by inventing a second, parallel result channel that
``engine.py`` (out of scope for this change) does not consume.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from typing import Any, Callable, Optional, Sequence

from scanner.security_operations import (
    CollectionResult,
    CollectionStatus,
    SecurityOperationsCollector,
    SecurityOperationsPolicy,
    load_security_operations_policy,
)

logger = logging.getLogger(__name__)

# The policy file is organisation-owned and is never loaded by default (see
# docs/security-operations-rules.md). A rule that cannot resolve a policy
# path has no approved scope, destinations, retention, or SLA to evaluate
# against, so its only safe outcome is UNKNOWN — never PASS and never FAIL.
POLICY_PATH_ENV_VAR = "OPENSHIELD_SECURITY_OPERATIONS_POLICY"


def value(item: Any, field: str, default: Any = None) -> Any:
    """Read an SDK model or test dictionary field without raising."""
    if item is None:
        return default
    if isinstance(item, dict):
        return item.get(field, default)
    return getattr(item, field, default)


def enum_value(item: Any) -> str:
    """Normalise an Azure SDK enum-like value (or plain string) to a lowercase string."""
    if item is None:
        return ""
    return str(getattr(item, "value", item)).strip().lower()


def load_policy_from_env(rule_id: str) -> Optional[SecurityOperationsPolicy]:
    """Load the organisation's security-operations policy from the configured path.

    Returns ``None`` (never raises) when the environment variable is unset,
    the file is missing, or the file fails strict validation — every caller
    must treat ``None`` as UNKNOWN, not as "no policy required".
    """
    path = os.environ.get(POLICY_PATH_ENV_VAR)
    if not path:
        logger.warning(
            "%s: %s is not set; security-operations policy is unavailable, result is UNKNOWN",
            rule_id,
            POLICY_PATH_ENV_VAR,
        )
        return None
    try:
        return load_security_operations_policy(path)
    except Exception as exc:
        logger.warning("%s: failed to load security-operations policy from %s: %s", rule_id, path, exc)
        return None


def default_resource_inventory(credential: Any, subscription_id: str) -> Callable[[], Sequence[Any]]:
    """Build a resource_inventory callable backed by the generic ARM resource list.

    ``SecurityOperationsCollector.critical_resource_ids`` needs a callable
    returning every resource in the subscription (id + type only). No
    existing AzureClient method returns a generic, subscription-wide
    inventory, so this uses azure-mgmt-resource directly — the standard SDK
    for enumerating resources across all providers/types.
    """

    def _list() -> Sequence[Any]:
        from azure.mgmt.resource import ResourceManagementClient

        client = ResourceManagementClient(credential, subscription_id)
        return list(client.resources.list())

    return _list


def build_collector(azure_client: Any, subscription_id: str) -> SecurityOperationsCollector:
    """Build a SecurityOperationsCollector from the AzureClient supplied to scan()."""
    credential = getattr(azure_client, "credential", None)
    return SecurityOperationsCollector(
        credential,
        subscription_id,
        resource_inventory=default_resource_inventory(credential, subscription_id),
    )


def is_usable(result: CollectionResult[Any]) -> bool:
    """Return True when a CollectionResult has at least partial evidence to evaluate."""
    return result.status in (CollectionStatus.COMPLETE, CollectionStatus.PARTIAL)


def evidence_timestamp() -> str:
    """Return the evidence-collection timestamp used on every finding (UTC, ISO 8601)."""
    return datetime.now(timezone.utc).isoformat()


def is_excluded(resource_id: str, policy: SecurityOperationsPolicy) -> bool:
    """Return True when a resource ID matches an organisation-approved exclusion.

    Exclusions are matched case-insensitively against the full resource ID so
    an approved exception never produces a false FAIL finding.
    """
    normalised = str(resource_id or "").strip().lower()
    return normalised in policy.approved_exclusions


def build_finding(
    *,
    rule_id: str,
    rule_name: str,
    severity: str,
    category: str,
    resource_id: str,
    resource_name: str,
    resource_type: str,
    description: str,
    remediation: str,
    playbook: str,
    frameworks: dict,
    scope: str,
    confidence: str = "HIGH",
    metadata: Optional[dict] = None,
) -> dict:
    """Build a finding dict carrying the issue #262 required metadata fields.

    ``scope``, ``category``, ``destination``, ``retention``, ``ownership``,
    ``evidence_collected_at``, ``remediation``, ``permissions_required``,
    ``severity``, and ``confidence`` all live under ``metadata`` alongside
    the rule-specific fields the caller supplies, so nothing in the required
    field list is dropped even though the top-level finding shape must match
    every other rule in this repo (see _REQUIRED_FIELDS in
    tests/test_rules_keyvault.py).
    """
    merged_metadata = {
        "scope": scope,
        "evidence_collected_at": evidence_timestamp(),
        "confidence": confidence,
    }
    merged_metadata.update(metadata or {})
    return {
        "rule_id": rule_id,
        "rule_name": rule_name,
        "severity": severity,
        "category": category,
        "resource_id": resource_id,
        "resource_name": resource_name,
        "resource_type": resource_type,
        "description": description,
        "remediation": remediation,
        "playbook": playbook,
        "frameworks": frameworks,
        "metadata": merged_metadata,
    }
