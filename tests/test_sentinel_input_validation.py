"""Validation tests for the Sentinel JSON ingestion boundary."""

import json

import pytest

from api.validation import ValidationError
from sentinel.ingest import load_findings, normalise


def test_load_findings_rejects_non_json_path(tmp_path):
    path = tmp_path / "findings.txt"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(ValidationError, match="JSON file"):
        load_findings(path)


def test_load_findings_rejects_wrong_shape(tmp_path):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps({"findings": "not-a-list"}), encoding="utf-8")
    with pytest.raises(ValidationError, match="findings list"):
        load_findings(path)


def test_normalise_rejects_non_object_and_invalid_severity():
    with pytest.raises(ValidationError, match="object"):
        normalise("finding", "scan-1")
    with pytest.raises(ValidationError, match="severity"):
        normalise({"severity": "urgent"}, "scan-1")


def test_normalise_accepts_bounded_finding():
    record = normalise(
        {"id": 1, "severity": "HIGH", "rule_id": "AZ-NET-001", "compliance": {"cis": "1.1"}},
        "scan-1",
    )
    assert record["Severity"] == "High"
    assert record["RuleId"] == "AZ-NET-001"
