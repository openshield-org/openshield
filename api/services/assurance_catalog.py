"""Shared validation primitives for closed assurance catalogs."""

from __future__ import annotations

from datetime import date
from typing import Any
from urllib.parse import urlparse


class CatalogValidationError(ValueError):
    """Raised when a bundled assurance catalog is incomplete or unsafe."""


def require_string(item: dict[str, Any], field: str, context: str) -> str:
    """Return a required non-empty string field."""
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CatalogValidationError(f"{context}: {field} must be a non-empty string")
    return value


def require_unique(items: Any, name: str) -> dict[str, dict[str, Any]]:
    """Index a required object list by unique string ID."""
    if not isinstance(items, list):
        raise CatalogValidationError(f"{name} must be a list")
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise CatalogValidationError(f"{name}: every entry must be an object")
        item_id = require_string(item, "id", name)
        if item_id in indexed:
            raise CatalogValidationError(f"{name}: duplicate id {item_id}")
        indexed[item_id] = item
    return indexed


def require_reference_list(item: dict[str, Any], field: str, allowed_ids: set[str], context: str) -> list[str]:
    """Validate a non-empty list of unique cross-references."""
    values = item.get(field)
    if not isinstance(values, list) or not values:
        raise CatalogValidationError(f"{context}: {field} must be a non-empty list")
    if any(not isinstance(value, str) for value in values):
        raise CatalogValidationError(f"{context}: {field} must contain only strings")
    if len(values) != len(set(values)):
        raise CatalogValidationError(f"{context}: {field} contains duplicate references")
    unknown = set(values) - allowed_ids
    if unknown:
        raise CatalogValidationError(f"{context}: {field} contains unknown ids {sorted(unknown)}")
    return values


def parse_iso_date(value: Any, context: str) -> date:
    """Parse a required ISO-8601 calendar date."""
    if not isinstance(value, str):
        raise CatalogValidationError(f"{context}: date must be an ISO-8601 string")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise CatalogValidationError(f"{context}: invalid ISO-8601 date {value!r}") from exc


def validate_evidence_source(source: dict[str, Any], source_id: str, allowed_hosts: set[str]) -> tuple[date, date]:
    """Validate common evidence metadata and return its review dates."""
    require_string(source, "title", source_id)
    url = require_string(source, "url", source_id)
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https" or parsed_url.hostname not in allowed_hosts:
        raise CatalogValidationError(f"{source_id}: evidence URL must use HTTPS on an allowed host")
    reviewed_at = parse_iso_date(source.get("reviewed_at"), f"{source_id}.reviewed_at")
    review_due_at = parse_iso_date(source.get("review_due_at"), f"{source_id}.review_due_at")
    if review_due_at <= reviewed_at:
        raise CatalogValidationError(f"{source_id}: review_due_at must be after reviewed_at")
    return reviewed_at, review_due_at
