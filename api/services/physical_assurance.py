"""Load and validate Azure Physical-layer provider assurance evidence."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


CATALOG_PATH = Path(__file__).resolve().parents[2] / "compliance" / "assurance" / "physical_layer.json"

EXPECTED_MICROSOFT_CONTROLS = {f"PE-{number}" for number in range(1, 9)}
EXPECTED_ISO_CONTROLS = {
    *(f"A.11.1.{number}" for number in range(1, 7)),
    *(f"A.11.2.{number}" for number in range(1, 10)),
}
EXPECTED_DOMAIN_IDS = {f"PHY-{number:02d}" for number in range(1, 22)}
EXPECTED_SUBLAYER_IDS = {
    "GENERIC-L1",
    "IEEE-PLCP",
    "IEEE-PCS",
    "IEEE-FEC",
    "IEEE-PMA",
    "IEEE-PMD",
    "IEEE-AN",
    "IEEE-MDI",
}
ALLOWED_STATUSES = {"PROVIDER_ATTESTED", "REVIEW_DUE", "NOT_APPLICABLE", "UNKNOWN"}
ALLOWED_EVIDENCE_HOSTS = {"learn.microsoft.com"}


class CatalogValidationError(ValueError):
    """Raised when the bundled assurance catalog is incomplete or unsafe."""


def _require_string(item: dict[str, Any], field: str, context: str) -> str:
    value = item.get(field)
    if not isinstance(value, str) or not value.strip():
        raise CatalogValidationError(f"{context}: {field} must be a non-empty string")
    return value


def _require_unique(items: list[dict[str, Any]], name: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise CatalogValidationError(f"{name}: every entry must be an object")
        item_id = _require_string(item, "id", name)
        if item_id in indexed:
            raise CatalogValidationError(f"{name}: duplicate id {item_id}")
        indexed[item_id] = item
    return indexed


def _require_reference_list(item: dict[str, Any], field: str, allowed_ids: set[str], context: str) -> list[str]:
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


def _parse_date(value: Any, context: str) -> date:
    if not isinstance(value, str):
        raise CatalogValidationError(f"{context}: date must be an ISO-8601 string")
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise CatalogValidationError(f"{context}: invalid ISO-8601 date {value!r}") from exc


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    """Load and validate a physical assurance catalog from disk."""
    try:
        with path.open(encoding="utf-8") as catalog_file:
            catalog = json.load(catalog_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogValidationError(f"Unable to load physical assurance catalog: {exc}") from exc

    validate_catalog(catalog)
    return catalog


def validate_catalog(catalog: dict[str, Any]) -> None:
    """Enforce the closed Layer 1 catalog and all cross-reference invariants."""
    if not isinstance(catalog, dict):
        raise CatalogValidationError("Catalog root must be an object")

    layer = catalog.get("layer")
    if not isinstance(layer, dict) or layer.get("number") != 1 or layer.get("name") != "Physical":
        raise CatalogValidationError("Catalog must describe OSI Layer 1 Physical")

    scope = catalog.get("scope")
    if not isinstance(scope, dict):
        raise CatalogValidationError("scope must be an object")
    if scope.get("environment") != "azure_public_cloud":
        raise CatalogValidationError("scope.environment must be azure_public_cloud")
    if scope.get("owner") != "Microsoft" or scope.get("runtime_hardware_observable") is not False:
        raise CatalogValidationError("Azure physical infrastructure must be Microsoft-owned and unobservable")

    domains = catalog.get("domains")
    sublayers = catalog.get("sublayers")
    evidence_sources = catalog.get("evidence_sources")
    controls = catalog.get("controls")
    if not all(isinstance(items, list) for items in (domains, sublayers, evidence_sources, controls)):
        raise CatalogValidationError("domains, sublayers, evidence_sources, and controls must be lists")

    domain_index = _require_unique(domains, "domains")
    sublayer_index = _require_unique(sublayers, "sublayers")
    evidence_index = _require_unique(evidence_sources, "evidence_sources")
    control_index = _require_unique(controls, "controls")

    if set(domain_index) != EXPECTED_DOMAIN_IDS:
        raise CatalogValidationError("domains must contain the complete PHY-01 through PHY-21 set")
    if set(sublayer_index) != EXPECTED_SUBLAYER_IDS:
        raise CatalogValidationError("sublayers must contain the complete generic and IEEE PHY set")
    if len(control_index) != 23:
        raise CatalogValidationError("controls must contain exactly 23 baseline controls")

    methodology = catalog.get("methodology")
    if not isinstance(methodology, dict):
        raise CatalogValidationError("methodology must be an object")
    expected_counts = {
        "baseline_control_count": len(control_index),
        "domain_count": len(domain_index),
        "sublayer_count": len(sublayer_index),
    }
    for field, expected in expected_counts.items():
        if methodology.get(field) != expected:
            raise CatalogValidationError(f"methodology.{field} must equal {expected}")

    for domain_id, domain in domain_index.items():
        _require_string(domain, "name", domain_id)
        _require_string(domain, "description", domain_id)

    domain_ids = set(domain_index)
    sublayer_ids = set(sublayer_index)
    evidence_ids = set(evidence_index)

    for sublayer_id, sublayer in sublayer_index.items():
        _require_string(sublayer, "name", sublayer_id)
        _require_string(sublayer, "profile", sublayer_id)
        _require_string(sublayer, "description", sublayer_id)
        _require_reference_list(sublayer, "domain_ids", domain_ids, sublayer_id)

    for evidence_id, evidence in evidence_index.items():
        _require_string(evidence, "title", evidence_id)
        _require_string(evidence, "evidence_type", evidence_id)
        url = _require_string(evidence, "url", evidence_id)
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https" or parsed_url.hostname not in ALLOWED_EVIDENCE_HOSTS:
            raise CatalogValidationError(f"{evidence_id}: evidence URL must use HTTPS on an allowed host")
        reviewed_at = _parse_date(evidence.get("reviewed_at"), f"{evidence_id}.reviewed_at")
        review_due_at = _parse_date(evidence.get("review_due_at"), f"{evidence_id}.review_due_at")
        if review_due_at <= reviewed_at:
            raise CatalogValidationError(f"{evidence_id}: review_due_at must be after reviewed_at")

    microsoft_controls: set[str] = set()
    iso_controls: set[str] = set()
    referenced_domains: set[str] = set()
    referenced_sublayers: set[str] = set()
    referenced_evidence: set[str] = set()

    for control_id, control in control_index.items():
        framework = _require_string(control, "framework", control_id)
        baseline_id = _require_string(control, "control_id", control_id)
        _require_string(control, "title", control_id)
        if control.get("responsibility") != "Microsoft":
            raise CatalogValidationError(f"{control_id}: responsibility must be Microsoft")
        if control.get("applicability") != "APPLICABLE":
            raise CatalogValidationError(f"{control_id}: Azure baseline controls must be APPLICABLE")
        if control.get("verification") != "PROVIDER_ASSURANCE":
            raise CatalogValidationError(f"{control_id}: verification must be PROVIDER_ASSURANCE")
        if control.get("status") not in ALLOWED_STATUSES:
            raise CatalogValidationError(f"{control_id}: unsupported status {control.get('status')!r}")

        control_sublayers = _require_reference_list(control, "sublayer_ids", sublayer_ids, control_id)
        control_domains = _require_reference_list(control, "domain_ids", domain_ids, control_id)
        control_evidence = _require_reference_list(control, "evidence_source_ids", evidence_ids, control_id)
        referenced_sublayers.update(control_sublayers)
        referenced_domains.update(control_domains)
        referenced_evidence.update(control_evidence)

        if framework == "Microsoft SOC":
            microsoft_controls.add(baseline_id)
        elif framework == "ISO/IEC 27001:2013":
            iso_controls.add(baseline_id)
        else:
            raise CatalogValidationError(f"{control_id}: unsupported baseline framework {framework!r}")

    if microsoft_controls != EXPECTED_MICROSOFT_CONTROLS:
        raise CatalogValidationError("Microsoft baseline must contain PE-1 through PE-8 exactly once")
    if iso_controls != EXPECTED_ISO_CONTROLS:
        raise CatalogValidationError("ISO baseline must contain all fifteen A.11 controls exactly once")
    if referenced_domains != domain_ids:
        raise CatalogValidationError(f"Uncovered physical domains: {sorted(domain_ids - referenced_domains)}")
    if referenced_sublayers != sublayer_ids:
        raise CatalogValidationError(f"Uncovered physical sublayers: {sorted(sublayer_ids - referenced_sublayers)}")
    if referenced_evidence != evidence_ids:
        raise CatalogValidationError(f"Unreferenced evidence sources: {sorted(evidence_ids - referenced_evidence)}")


def build_report(catalog: dict[str, Any], as_of: date | None = None) -> dict[str, Any]:
    """Build the API report while keeping coverage and freshness independent."""
    validate_catalog(catalog)
    report = copy.deepcopy(catalog)
    as_of = as_of or date.today()

    evidence_by_id = {item["id"]: item for item in report["evidence_sources"]}
    current_controls = 0
    status_counts = {status: 0 for status in ALLOWED_STATUSES}

    for control in report["controls"]:
        expanded_evidence = [evidence_by_id[source_id] for source_id in control["evidence_source_ids"]]
        evidence_current = all(date.fromisoformat(item["review_due_at"]) >= as_of for item in expanded_evidence)
        if not evidence_current and control["status"] == "PROVIDER_ATTESTED":
            control["status"] = "REVIEW_DUE"
        control["evidence_current"] = evidence_current
        control["evidence"] = expanded_evidence
        current_controls += int(evidence_current)
        status_counts[control["status"]] += 1

    control_ids_by_domain = {
        domain["id"]: [control["id"] for control in report["controls"] if domain["id"] in control["domain_ids"]]
        for domain in report["domains"]
    }
    sublayer_ids_by_domain = {
        domain["id"]: [sublayer["id"] for sublayer in report["sublayers"] if domain["id"] in sublayer["domain_ids"]]
        for domain in report["domains"]
    }
    for domain in report["domains"]:
        domain["control_ids"] = control_ids_by_domain[domain["id"]]
        domain["sublayer_ids"] = sublayer_ids_by_domain[domain["id"]]
    for sublayer in report["sublayers"]:
        sublayer["control_ids"] = [
            control["id"] for control in report["controls"] if sublayer["id"] in control["sublayer_ids"]
        ]

    total_controls = len(report["controls"])
    report["summary"] = {
        "baseline_controls": total_controls,
        "covered_controls": total_controls,
        "coverage_percent": 100,
        "domains": len(report["domains"]),
        "covered_domains": len(report["domains"]),
        "sublayers": len(report["sublayers"]),
        "covered_sublayers": len(report["sublayers"]),
        "evidence_current_controls": current_controls,
        "evidence_current_percent": round((current_controls / total_controls) * 100) if total_controls else 0,
        "status_counts": status_counts,
        "assessed_as_of": as_of.isoformat(),
    }
    report["limitations"] = [
        "This is provider-assurance coverage, not a live scan of Microsoft datacenter hardware.",
        "A 100 percent catalog score does not assert tenant compliance or certify physical infrastructure.",
        "Expired evidence is reported as REVIEW_DUE and never converted into a technical security finding.",
    ]
    return report


def get_physical_assurance_report(as_of: date | None = None) -> dict[str, Any]:
    """Load the bundled catalog and return its derived assurance report."""
    return build_report(load_catalog(), as_of=as_of)
