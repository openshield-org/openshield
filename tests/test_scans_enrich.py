"""Tests for POST /api/scans/<id>/enrich backgrounding (REL-004)."""

from unittest.mock import MagicMock, patch

import api.routes.scans as scans_route

_SCAN_ID = "00000000-0000-0000-0000-000000000001"


def _mock_db(current_scan=None, findings=None):
    db = MagicMock()
    db.get_scans.return_value = [current_scan] if current_scan else []
    db.get_findings.return_value = findings if findings is not None else []
    return db


class _FakeThread:
    """Records what would have been threaded, and runs synchronously on start()."""

    last_instance = None

    def __init__(self, target, args, daemon):
        self.target = target
        self.args = args
        self.daemon = daemon
        self.started = False
        _FakeThread.last_instance = self

    def start(self):
        self.started = True


def test_enrich_returns_202_and_schedules_background_thread(client, auth_headers, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://mock/mock")
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
    findings = [{"id": 1, "rule_id": "AZ-STOR-001"}]
    db = _mock_db(current_scan=scan, findings=findings)

    with (
        patch.object(scans_route, "_get_db", return_value=db),
        patch.object(scans_route.threading, "Thread", _FakeThread),
    ):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)

    assert resp.status_code == 202
    body = resp.get_json()
    assert body["status"] == "ENRICHING"

    db.update_scan_enrichment_status.assert_called_once_with(_SCAN_ID, "ENRICHING")

    thread = _FakeThread.last_instance
    assert thread.started is True
    assert thread.daemon is True
    assert thread.target is scans_route._run_enrichment_in_background
    assert thread.args[0] == _SCAN_ID
    assert thread.args[1] == findings


def test_enrich_already_completed_returns_200(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "COMPLETED"}
    db = _mock_db(current_scan=scan)
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 200
    assert "already enriched" in resp.get_json()["message"]


def test_enrich_already_in_progress_returns_202(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "ENRICHING"}
    db = _mock_db(current_scan=scan)
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 202
    assert "in progress" in resp.get_json()["message"]


def test_enrich_missing_scan_returns_404(client, auth_headers):
    db = _mock_db(current_scan=None)
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 404


def test_enrich_no_findings_returns_404(client, auth_headers):
    scan = {"scan_id": _SCAN_ID, "cve_enrichment_status": "PENDING"}
    db = _mock_db(current_scan=scan, findings=[])
    with patch.object(scans_route, "_get_db", return_value=db):
        resp = client.post(f"/api/scans/{_SCAN_ID}/enrich", headers=auth_headers)
    assert resp.status_code == 404


def test_background_enrichment_marks_completed_on_success():
    fake_db = MagicMock()
    with (
        patch.object(scans_route, "DatabaseManager", return_value=fake_db),
        patch.object(scans_route, "enrich_findings", return_value=[{"id": 1}]),
    ):
        scans_route._run_enrichment_in_background("scan-1", [{"id": 1}], "postgresql://mock/mock")

    fake_db.update_cve_fields.assert_called_once_with([{"id": 1}])
    fake_db.update_scan_enrichment_status.assert_called_once_with("scan-1", "COMPLETED")
    fake_db.close.assert_called_once()


def test_background_enrichment_marks_failed_on_error():
    fake_db = MagicMock()
    with (
        patch.object(scans_route, "DatabaseManager", return_value=fake_db),
        patch.object(scans_route, "enrich_findings", side_effect=RuntimeError("boom")),
    ):
        scans_route._run_enrichment_in_background("scan-1", [{"id": 1}], "postgresql://mock/mock")

    fake_db.update_scan_enrichment_status.assert_called_once_with("scan-1", "FAILED")
    fake_db.close.assert_called_once()


def test_background_enrichment_rolls_back_before_marking_failed():
    """A write failure (e.g. in update_cve_fields) can leave db.conn in an
    aborted-transaction state. Without a rollback first, the follow-up
    update_scan_enrichment_status(FAILED) call would itself raise
    InFailedSqlTransaction and get silently swallowed, leaving the scan
    stuck at ENRICHING forever."""
    fake_db = MagicMock()
    fake_db.conn = MagicMock()  # an open connection, left mid-transaction
    with (
        patch.object(scans_route, "DatabaseManager", return_value=fake_db),
        patch.object(scans_route, "enrich_findings", side_effect=RuntimeError("boom")),
    ):
        scans_route._run_enrichment_in_background("scan-1", [{"id": 1}], "postgresql://mock/mock")

    fake_db.conn.rollback.assert_called_once()
    fake_db.update_scan_enrichment_status.assert_called_once_with("scan-1", "FAILED")


def test_background_enrichment_skips_rollback_when_never_connected():
    """If enrich_findings() fails before any DB write, db.conn is still None
    — rollback() must not be called on it."""
    fake_db = MagicMock()
    fake_db.conn = None
    with (
        patch.object(scans_route, "DatabaseManager", return_value=fake_db),
        patch.object(scans_route, "enrich_findings", side_effect=RuntimeError("boom")),
    ):
        scans_route._run_enrichment_in_background("scan-1", [{"id": 1}], "postgresql://mock/mock")

    fake_db.update_scan_enrichment_status.assert_called_once_with("scan-1", "FAILED")
