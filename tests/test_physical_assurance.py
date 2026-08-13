"""Completeness and API tests for Azure Physical-layer provider assurance."""

import copy
from datetime import date
from unittest.mock import patch

import pytest

from api.services.physical_assurance import (
    EXPECTED_DOMAIN_IDS,
    EXPECTED_ISO_CONTROLS,
    EXPECTED_MICROSOFT_CONTROLS,
    EXPECTED_SUBLAYER_IDS,
    CatalogValidationError,
    build_report,
    load_catalog,
    validate_catalog,
)


def test_catalog_covers_every_baseline_control_domain_and_sublayer():
    catalog = load_catalog()

    microsoft_controls = {
        control["control_id"] for control in catalog["controls"] if control["framework"] == "Microsoft SOC"
    }
    iso_controls = {
        control["control_id"] for control in catalog["controls"] if control["framework"] == "ISO/IEC 27001:2013"
    }
    covered_domains = {domain_id for control in catalog["controls"] for domain_id in control["domain_ids"]}
    covered_sublayers = {sublayer_id for control in catalog["controls"] for sublayer_id in control["sublayer_ids"]}

    assert microsoft_controls == EXPECTED_MICROSOFT_CONTROLS
    assert iso_controls == EXPECTED_ISO_CONTROLS
    assert covered_domains == EXPECTED_DOMAIN_IDS
    assert covered_sublayers == EXPECTED_SUBLAYER_IDS
    assert len(catalog["controls"]) == 23


def test_report_expands_bidirectional_domain_and_sublayer_mappings():
    report = build_report(load_catalog(), as_of=date(2026, 8, 8))

    assert report["summary"]["coverage_percent"] == 100
    assert report["summary"]["covered_controls"] == 23
    assert report["summary"]["covered_domains"] == 21
    assert report["summary"]["covered_sublayers"] == 8
    assert all(domain["control_ids"] for domain in report["domains"])
    assert all(sublayer["control_ids"] for sublayer in report["sublayers"])
    assert all(control["evidence"] for control in report["controls"])


def test_expired_evidence_does_not_become_a_false_scan_failure():
    report = build_report(load_catalog(), as_of=date(2027, 8, 9))

    assert report["summary"]["coverage_percent"] == 100
    assert report["summary"]["evidence_current_percent"] == 0
    assert report["summary"]["status_counts"]["REVIEW_DUE"] == 23
    assert report["summary"]["status_counts"]["UNKNOWN"] == 0
    assert {control["status"] for control in report["controls"]} == {"REVIEW_DUE"}


@pytest.mark.parametrize(
    ("collection", "removed_id", "error_match"),
    [
        ("domains", "PHY-21", "complete PHY-01 through PHY-21"),
        ("sublayers", "IEEE-PMD", "complete generic and IEEE PHY set"),
        ("controls", "MS-PE-8", "exactly 23 baseline controls"),
    ],
)
def test_catalog_rejects_missing_required_entries(collection, removed_id, error_match):
    catalog = copy.deepcopy(load_catalog())
    catalog[collection] = [item for item in catalog[collection] if item["id"] != removed_id]

    with pytest.raises(CatalogValidationError, match=error_match):
        validate_catalog(catalog)


def test_catalog_rejects_unobservable_control_claimed_as_automated():
    catalog = copy.deepcopy(load_catalog())
    catalog["controls"][0]["verification"] = "AUTOMATED_SCAN"

    with pytest.raises(CatalogValidationError, match="verification must be PROVIDER_ASSURANCE"):
        validate_catalog(catalog)


def test_catalog_rejects_untrusted_or_insecure_evidence_url():
    catalog = copy.deepcopy(load_catalog())
    catalog["evidence_sources"][0]["url"] = "http://example.com/untrusted"

    with pytest.raises(CatalogValidationError, match="HTTPS on an allowed host"):
        validate_catalog(catalog)


def test_physical_assurance_endpoint_requires_authentication(client):
    response = client.get("/api/assurance/physical-layer")

    assert response.status_code == 401


def test_physical_assurance_endpoint_returns_complete_report(client, auth_headers):
    response = client.get("/api/assurance/physical-layer", headers=auth_headers)

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["layer"] == {
        "assessment_type": "provider_assurance",
        "model": "OSI",
        "name": "Physical",
        "number": 1,
    }
    assert payload["scope"]["runtime_hardware_observable"] is False
    assert payload["summary"]["coverage_percent"] == 100
    assert len(payload["controls"]) == 23
    assert len(payload["domains"]) == 21
    assert len(payload["sublayers"]) == 8


def test_physical_assurance_endpoint_hides_catalog_error_details(client, auth_headers):
    marker = "sensitive catalog path"
    with patch(
        "api.routes.assurance.get_physical_assurance_report",
        side_effect=CatalogValidationError(marker),
    ):
        response = client.get("/api/assurance/physical-layer", headers=auth_headers)

    assert response.status_code == 500
    assert response.get_json() == {"error": "Physical assurance catalog is unavailable"}
    assert marker not in response.get_data(as_text=True)


def test_physical_assurance_does_not_add_fake_scanner_rules():
    from pathlib import Path

    rules_dir = Path(__file__).parent.parent / "scanner" / "rules"
    assert not list(rules_dir.glob("az_phy_*.py"))
