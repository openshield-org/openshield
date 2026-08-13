"""Tests for the CIS Azure Foundations Benchmark mapping file (COR-005, COR-006)."""

import json
from collections import Counter
from pathlib import Path

_CIS_PATH = Path(__file__).parent.parent / "compliance" / "frameworks" / "cis_azure_benchmark.json"


def _load_controls():
    with open(_CIS_PATH, encoding="utf-8") as f:
        return json.load(f)["controls"]


def test_no_duplicate_cis_control_ids():
    """CIS is an enumerated checklist: each numbered control should map to
    exactly one OpenShield rule, unlike NIST/ISO/SOC2 which are broad
    principle-based frameworks where many-to-one is legitimate."""
    controls = _load_controls()
    control_ids = [c["control_id"] for c in controls.values()]
    counts = Counter(control_ids)
    duplicates = {cid: n for cid, n in counts.items() if n > 1}
    assert duplicates == {}, f"Duplicate CIS control_id values found: {duplicates}"


def test_az_cmp_001_maps_to_its_own_distinct_control():
    """AZ-CMP-001 (VM public IP with no NSG) previously had control_id 7.2
    copy-pasted from AZ-CMP-002 (OS disk encryption) — an unrelated control."""
    controls = _load_controls()
    cmp_001 = controls["AZ-CMP-001"]
    cmp_002 = controls["AZ-CMP-002"]

    assert cmp_001["control_id"] != cmp_002["control_id"]
    assert "disk" not in cmp_001["control_name"].lower()
    assert "network security group" in cmp_001["control_name"].lower()


def test_all_rule_files_agree_with_the_cis_mapping_file():
    """Each rule's own FRAMEWORKS["CIS"] value (shown per-finding) must match
    the authoritative compliance/frameworks/cis_azure_benchmark.json entry
    used for scoring, or the two would silently disagree."""
    import importlib

    controls = _load_controls()
    mismatches = []
    for rule_id, control in controls.items():
        module_name = "scanner.rules." + rule_id.lower().replace("-", "_")
        module = importlib.import_module(module_name)
        rule_cis = module.FRAMEWORKS.get("CIS")
        if rule_cis != control["control_id"]:
            mismatches.append((rule_id, rule_cis, control["control_id"]))

    assert mismatches == [], f"rule_id, rule_FRAMEWORKS[CIS], json control_id: {mismatches}"


def test_cis_mapping_has_no_legacy_tbd_control_ids():
    """Unresolved TBD identifiers must never reach scoring or findings.

    N/A-* is the explicit, reviewed representation for controls that have no
    direct CIS recommendation; the old TBD-* prefix was only a placeholder.
    """
    controls = _load_controls()
    legacy = {
        rule_id: control["control_id"]
        for rule_id, control in controls.items()
        if control["control_id"].startswith("TBD-")
    }
    assert legacy == {}
