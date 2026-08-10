"""Load, validate, and report Azure Data Link assurance coverage."""

from __future__ import annotations

import copy
import json
from datetime import date
from pathlib import Path
from typing import Any

from api.services.assurance_catalog import (
    CatalogValidationError,
    require_reference_list,
    require_string,
    require_unique,
    validate_evidence_source,
)

CATALOG_PATH = Path(__file__).resolve().parents[2] / "compliance" / "assurance" / "data_link_layer.json"
EXPECTED_DOMAIN_IDS = {f"DL-{number:02d}" for number in range(1, 20)}
EXPECTED_SUBLAYER_IDS = {"LLC", "MAC"}
ALLOWED_RESPONSIBILITIES = {"Microsoft", "Customer", "Shared"}
ALLOWED_APPLICABILITY = {"APPLICABLE", "NOT_APPLICABLE", "UNSUPPORTED"}
ALLOWED_VERIFICATION = {
    "PROVIDER_ATTESTED",
    "PLATFORM_ENFORCED",
    "AUTOMATICALLY_CHECKED",
    "MANUALLY_VERIFIABLE",
    "UNSUPPORTED",
    "NOT_APPLICABLE",
}


def validate_catalog(catalog: dict[str, Any]) -> None:
    """Fail closed when any Layer 2 domain, sublayer, decision, or cross-reference is missing."""
    if not isinstance(catalog, dict):
        raise CatalogValidationError("Catalog root must be an object")
    layer = catalog.get("layer")
    if not isinstance(layer, dict) or layer.get("number") != 2 or layer.get("name") != "Data Link":
        raise CatalogValidationError("Catalog must describe OSI Layer 2 Data Link")
    require_string(catalog, "catalog_version", "catalog")
    scope = catalog.get("scope")
    if not isinstance(scope, dict):
        raise CatalogValidationError("scope must be an object")
    require_string(scope, "statement", "scope")
    require_string(scope, "responsibility_boundary", "scope")

    domains = require_unique(catalog.get("domains"), "domains")
    sublayers = require_unique(catalog.get("sublayers"), "sublayers")
    evidence = require_unique(catalog.get("evidence_sources"), "evidence_sources")
    automated = require_unique(catalog.get("automated_controls"), "automated_controls")
    if set(domains) != EXPECTED_DOMAIN_IDS:
        raise CatalogValidationError("domains must contain the complete DL-01 through DL-19 set")
    if set(sublayers) != EXPECTED_SUBLAYER_IDS:
        raise CatalogValidationError("sublayers must contain LLC and MAC")

    for sublayer_id, sublayer in sublayers.items():
        require_string(sublayer, "name", sublayer_id)
        require_string(sublayer, "description", sublayer_id)
    for evidence_id, source in evidence.items():
        validate_evidence_source(source, evidence_id, {"learn.microsoft.com"})

    referenced_sublayers: set[str] = set()
    referenced_evidence: set[str] = set()
    referenced_automated: set[str] = set()
    for domain_id, domain in domains.items():
        require_string(domain, "name", domain_id)
        require_string(domain, "observability_method", domain_id)
        responsibility = require_string(domain, "responsibility_owner", domain_id)
        applicability = require_string(domain, "azure_applicability", domain_id)
        verification = require_string(domain, "verification", domain_id)
        if responsibility not in ALLOWED_RESPONSIBILITIES:
            raise CatalogValidationError(f"{domain_id}: invalid responsibility_owner")
        if applicability not in ALLOWED_APPLICABILITY:
            raise CatalogValidationError(f"{domain_id}: invalid azure_applicability")
        if verification not in ALLOWED_VERIFICATION:
            raise CatalogValidationError(f"{domain_id}: invalid verification")
        referenced_sublayers.update(require_reference_list(domain, "sublayer_ids", set(sublayers), domain_id))
        referenced_evidence.update(require_reference_list(domain, "evidence_source_ids", set(evidence), domain_id))
        control_ids = domain.get("automated_control_ids", [])
        if verification == "AUTOMATICALLY_CHECKED":
            referenced_automated.update(
                require_reference_list(domain, "automated_control_ids", set(automated), domain_id)
            )
        elif control_ids:
            raise CatalogValidationError(f"{domain_id}: only automatically checked domains may reference rules")
    if referenced_sublayers != set(sublayers):
        raise CatalogValidationError("LLC and MAC must both be covered")
    if referenced_evidence != set(evidence):
        raise CatalogValidationError("every evidence source must be referenced")
    if referenced_automated != set(automated):
        raise CatalogValidationError("every automated control must be cross-referenced")

    for control_id, control in automated.items():
        require_string(control, "name", control_id)
        require_string(control, "playbook", control_id)
        require_reference_list(control, "domain_ids", set(domains), control_id)
        frameworks = control.get("frameworks")
        if not isinstance(frameworks, dict) or set(frameworks) != {"CIS", "NIST", "ISO27001", "SOC2"}:
            raise CatalogValidationError(f"{control_id}: all required framework mappings must be present")


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    """Load and validate the bundled catalog."""
    try:
        with path.open(encoding="utf-8") as catalog_file:
            catalog = json.load(catalog_file)
    except (OSError, json.JSONDecodeError) as exc:
        raise CatalogValidationError(f"Unable to load Data Link assurance catalog: {exc}") from exc
    validate_catalog(catalog)
    return catalog


def build_report(catalog: dict[str, Any], as_of: date | None = None) -> dict[str, Any]:
    """Build static responsibility coverage with independent evidence freshness."""
    validate_catalog(catalog)
    report = copy.deepcopy(catalog)
    as_of = as_of or date.today()
    evidence = {item["id"]: item for item in report["evidence_sources"]}
    current = sum(date.fromisoformat(item["review_due_at"]) >= as_of for item in evidence.values())
    for domain in report["domains"]:
        domain["evidence"] = [evidence[source_id] for source_id in domain["evidence_source_ids"]]
    report["catalog_coverage"] = {
        "domains_covered": len(report["domains"]),
        "domains_total": 19,
        "sublayers_covered": 2,
        "sublayers_total": 2,
        "percent": 100,
    }
    report["evidence_freshness"] = {
        "current_sources": current,
        "total_sources": len(evidence),
        "percent": round(current / len(evidence) * 100) if evidence else 0,
        "assessed_as_of": as_of.isoformat(),
    }
    report["provider_assurance_state"] = "DOCUMENTED"
    report["platform_enforcement_state"] = "DOCUMENTED_NOT_LIVE_INSPECTED"
    report["automated_control_applicability"] = {
        "state": "REQUIRES_SUBSCRIPTION_INVENTORY",
        "without_expressroute_direct": "NOT_APPLICABLE",
        "api_or_permission_failure": "INDETERMINATE",
    }
    report["limitations"] = [
        "This report is not a live inspection of Microsoft switches, forwarding tables, VLANs, or fabric internals.",
        "Provider-owned assurance domains do not create findings or change the tenant security score.",
        "Only ExpressRoute Direct management-plane configuration is automatically checked.",
    ]
    return report


def get_data_link_assurance_report(as_of: date | None = None) -> dict[str, Any]:
    """Return the bundled Data Link assurance report."""
    return build_report(load_catalog(), as_of=as_of)
