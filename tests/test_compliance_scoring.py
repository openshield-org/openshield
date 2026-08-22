"""Tests for the compliance mapping-pack scoring in DatabaseManager.get_compliance_score()
and the mapping-pack snapshot persisted by save_scan() (issue #302)."""

import json
from unittest.mock import MagicMock, patch

import api.models.finding as finding_module
import api.routes.compliance as compliance_route


def _db(dsn="postgresql://mock/mock"):
    db = finding_module.DatabaseManager.__new__(finding_module.DatabaseManager)
    db.dsn = dsn
    db.conn = None
    return db


def _mock_cursor(fetchone_return=None, fetchall_return=None):
    cur = MagicMock()
    cur.__enter__ = lambda s: s
    cur.__exit__ = MagicMock(return_value=False)
    cur.fetchone.return_value = fetchone_return
    cur.fetchall.return_value = fetchall_return or []
    return cur


def _write_framework(tmp_path, filename, controls, **pack_overrides):
    data = {
        "framework": "Test Framework",
        "version": "1.0",
        "published": "2026-01",
        "mapping_pack_version": "1.0.0",
        "mapping_pack_status": "current",
        "mapping_pack_source": "test fixture",
        "mapping_pack_published": "2026-08-22",
        "controls": controls,
    }
    data.update(pack_overrides)
    path = tmp_path / filename
    with open(path, "w") as fh:
        json.dump(data, fh)
    return path


def _control(control_id, mapping_type="direct"):
    return {
        "control_id": control_id,
        "control_name": f"Control {control_id}",
        "description": "test",
        "mapping_type": mapping_type,
        "evidence_type": "not_applicable"
        if mapping_type in ("not_applicable", "organizational")
        else "automated_configuration_scan",
        "primary_source": "test source",
        "rationale": "test rationale",
        "owner": None,
        "review_status": "pending_review",
        "review_date": None,
    }


# ── No completed scan: must never report a passing score from absent data ──


def test_no_completed_scan_returns_no_scan_data_not_a_pass():
    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor(fetchone_return=None)
    with (
        patch.object(db, "_get_conn", return_value=conn),
        patch.object(finding_module, "FRAMEWORKS_DIR", finding_module.FRAMEWORKS_DIR),
    ):
        result = db.get_compliance_score("cis")

    assert result["status"] == "NO_SCAN_DATA"
    assert result["score_percent"] is None
    assert result["passed"] == 0
    assert result["failed"] == 0
    assert "error" not in result  # route must return 200, not 500, for this normal state
    assert result["controls"] == []


# ── Unknown framework / missing file ────────────────────────────────────────


def test_unknown_framework_returns_error():
    db = _db()
    result = db.get_compliance_score("not-a-real-framework")
    assert "error" in result


# ── PASS / FAIL / exclusion semantics, using a synthetic framework file ────


def _patched_db_with_framework(tmp_path, controls, scan_row, finding_rows):
    db = _db()
    conn = MagicMock()
    cur = _mock_cursor(fetchone_return=scan_row, fetchall_return=finding_rows)
    conn.cursor.return_value = cur

    framework_file = "test_fw.json"
    _write_framework(tmp_path, framework_file, controls)

    return db, conn, framework_file


def test_direct_control_with_no_findings_is_pass(tmp_path, monkeypatch):
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["controls"][0]["status"] == "PASS"
    assert result["passed"] == 1
    assert result["failed"] == 0
    assert result["score_percent"] == 100


def test_control_with_finding_is_fail(tmp_path, monkeypatch):
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
    finding_rows = [{"rule_id": "AZ-TEST-001"}]
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, finding_rows)

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    assert result["controls"][0]["status"] == "FAIL"
    assert result["passed"] == 0
    assert result["failed"] == 1
    assert result["score_percent"] == 0


def test_not_applicable_and_organizational_excluded_from_denominator(tmp_path, monkeypatch):
    controls = {
        "AZ-TEST-001": _control("1.1", "direct"),  # PASS
        "AZ-TEST-002": _control("1.2", "direct"),  # FAIL
        "AZ-TEST-003": _control("1.3", "not_applicable"),
        "AZ-TEST-004": _control("1.4", "organizational"),
    }
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": None}
    finding_rows = [{"rule_id": "AZ-TEST-002"}]
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, finding_rows)

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    statuses = {c["rule_id"]: c["status"] for c in result["controls"]}
    assert statuses["AZ-TEST-001"] == "PASS"
    assert statuses["AZ-TEST-002"] == "FAIL"
    assert statuses["AZ-TEST-003"] == "NOT_APPLICABLE"
    assert statuses["AZ-TEST-004"] == "ORGANIZATIONAL"

    assert result["total_controls"] == 4
    assert result["excluded_controls"] == 2
    assert result["in_scope_controls"] == 2
    assert result["passed"] == 1
    assert result["failed"] == 1
    # Score is 1/2, not 1/4 — excluded controls must not dilute the denominator.
    assert result["score_percent"] == 50


def test_mapping_pack_snapshot_preferred_over_live_file(tmp_path, monkeypatch):
    controls = {"AZ-TEST-001": _control("1.1", "direct")}
    historical_snapshot = {
        "testfw": {
            "framework": "Test Framework (historical)",
            "version": "0.9",
            "mapping_pack_version": "0.1.0",
            "mapping_pack_status": "legacy",
            "mapping_pack_source": "historical fixture",
            "mapping_pack_published": "2025-01-01",
        }
    }
    scan_row = {"scan_id": "scan-1", "compliance_mapping_snapshot": historical_snapshot}
    db, conn, framework_file = _patched_db_with_framework(tmp_path, controls, scan_row, [])

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    monkeypatch.setitem(finding_module.FRAMEWORK_FILE_MAP, "testfw", framework_file)

    with patch.object(db, "_get_conn", return_value=conn):
        result = db.get_compliance_score("testfw")

    # Report shows what was true when the scan ran, not the current file on disk.
    assert result["mapping_pack_version"] == "0.1.0"
    assert result["mapping_pack_status"] == "legacy"
    assert result["framework"] == "Test Framework (historical)"


# ── compliance_mapping_snapshot construction for save_scan() ───────────────


def test_build_compliance_mapping_snapshot_reads_all_frameworks(tmp_path, monkeypatch):
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        _write_framework(tmp_path, filename, {})

    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    snapshot = finding_module._build_compliance_mapping_snapshot()

    assert set(snapshot.keys()) == set(finding_module.FRAMEWORK_FILE_MAP.keys())
    for entry in snapshot.values():
        assert entry["mapping_pack_version"] == "1.0.0"
        assert entry["mapping_pack_status"] == "current"


def test_build_compliance_mapping_snapshot_skips_missing_file(tmp_path, monkeypatch):
    # No framework files written at all — every FRAMEWORKS_DIR / filename lookup misses.
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)
    snapshot = finding_module._build_compliance_mapping_snapshot()
    assert snapshot == {}


def test_save_scan_persists_compliance_mapping_snapshot(tmp_path, monkeypatch):
    for key, filename in finding_module.FRAMEWORK_FILE_MAP.items():
        _write_framework(tmp_path, filename, {})
    monkeypatch.setattr(finding_module, "FRAMEWORKS_DIR", tmp_path)

    db = _db()
    conn = MagicMock()
    conn.cursor.return_value = _mock_cursor()
    with patch.object(db, "_get_conn", return_value=conn):
        db.save_scan(
            {
                "scan_id": "scan-1",
                "subscription_id": "sub-1",
                "started_at": "2026-08-22T00:00:00Z",
                "completed_at": "2026-08-22T00:05:00Z",
                "total_findings": 0,
                "findings": [],
            }
        )

    executed_sql, params = conn.cursor.return_value.execute.call_args_list[0][0]
    assert "compliance_mapping_snapshot" in executed_sql
    snapshot_param = params[-1]
    snapshot = json.loads(snapshot_param)
    assert set(snapshot.keys()) == set(finding_module.FRAMEWORK_FILE_MAP.keys())


# ── Route-level: /api/compliance/<framework> must degrade to 200, not 500,
#    when there is genuinely no scan evidence yet ──────────────────────────


def test_route_returns_200_for_no_scan_data(client, auth_headers):
    db = MagicMock()
    db.get_compliance_score.return_value = {
        "framework": "Test Framework",
        "version": "1.0",
        "status": "NO_SCAN_DATA",
        "message": "No completed scan is available yet.",
        "total_controls": 3,
        "in_scope_controls": 0,
        "excluded_controls": 0,
        "passed": 0,
        "failed": 0,
        "score_percent": None,
        "controls": [],
    }
    with patch.object(compliance_route, "_get_db", return_value=db):
        resp = client.get("/api/compliance/cis", headers=auth_headers)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["status"] == "NO_SCAN_DATA"
    assert body["score_percent"] is None


def test_route_reports_mapping_metadata_fields(client, auth_headers):
    db = MagicMock()
    db.get_compliance_score.return_value = {
        "framework": "Test Framework",
        "version": "1.0",
        "mapping_pack_version": "1.0.0",
        "mapping_pack_status": "current",
        "mapping_pack_source": "test",
        "mapping_pack_published": "2026-08-22",
        "scan_id": "scan-1",
        "evaluation_basis": "...",
        "total_controls": 1,
        "in_scope_controls": 1,
        "excluded_controls": 0,
        "passed": 1,
        "failed": 0,
        "score_percent": 100,
        "controls": [
            {
                "rule_id": "AZ-TEST-001",
                "control_id": "1.1",
                "control_name": "Control 1.1",
                "status": "PASS",
                "mapping_type": "direct",
                "evidence_type": "automated_configuration_scan",
                "primary_source": "test source",
                "rationale": "test rationale",
                "owner": None,
                "review_status": "pending_review",
                "review_date": None,
            }
        ],
    }
    with patch.object(compliance_route, "_get_db", return_value=db):
        resp = client.get("/api/compliance/cis", headers=auth_headers)

    assert resp.status_code == 200
    body = resp.get_json()
    assert body["mapping_pack_version"] == "1.0.0"
    assert body["controls"][0]["mapping_type"] == "direct"
    assert body["controls"][0]["rationale"] == "test rationale"
