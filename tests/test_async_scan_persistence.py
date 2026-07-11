"""Regression tests for DB-backed async scan state.

These tests protect against reintroducing an in-memory scan job store. The API
must persist queued scan state through DatabaseManager so status survives web
process restarts.
"""

from unittest.mock import MagicMock, patch

from api.models.finding import DatabaseManager


class _Cursor:
    def __init__(self, rows=None, rowcounts=None):
        self.rows = rows or []
        self.rowcounts = rowcounts or []
        self.calls = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def execute(self, sql, params=None):
        self.calls.append((sql, params))
        if self.rowcounts:
            self.rowcount = self.rowcounts.pop(0)

    def fetchone(self):
        if self.rows:
            return self.rows.pop(0)
        return None


def test_trigger_scan_persists_pending_scan_to_database(client, auth_headers, monkeypatch):
    """POST /api/scans/trigger should create a pending DB row, not an in-memory job."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://ci:ci@localhost/ci_db")
    scan_id = "11111111-1111-1111-1111-111111111111"
    subscription_id = "00000000-0000-0000-0000-000000000000"
    mock_db = MagicMock()

    with patch("api.routes.scans.DatabaseManager", return_value=mock_db) as db_class:
        with patch("api.routes.scans.uuid.uuid4", return_value=scan_id):
            resp = client.post(
                "/api/scans/trigger",
                json={"subscription_id": subscription_id},
                headers=auth_headers,
            )

    assert resp.status_code == 202
    assert resp.get_json() == {
        "scan_id": scan_id,
        "status": "pending",
        "message": "Scan has been queued and will start shortly.",
    }
    db_class.assert_called_once_with("postgresql://ci:ci@localhost/ci_db")
    mock_db.connect.assert_called_once()
    mock_db.create_pending_scan.assert_called_once_with(scan_id, subscription_id)


def test_get_scan_status_reads_from_database(client, auth_headers, monkeypatch):
    """GET /api/scans/<scan_id> should read durable status from PostgreSQL."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://ci:ci@localhost/ci_db")
    scan_id = "22222222-2222-2222-2222-222222222222"
    mock_db = MagicMock()
    mock_db.get_scan.return_value = {
        "scan_id": scan_id,
        "subscription_id": "00000000-0000-0000-0000-000000000000",
        "status": "running",
        "started_at": "2026-07-07T12:00:00Z",
        "completed_at": None,
        "total_findings": 0,
        "score": None,
        "error_message": None,
    }

    with patch("api.routes.scans.DatabaseManager", return_value=mock_db) as db_class:
        resp = client.get(f"/api/scans/{scan_id}", headers=auth_headers)

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "running"
    db_class.assert_called_once_with("postgresql://ci:ci@localhost/ci_db")
    mock_db.connect.assert_called_once()
    mock_db.get_scan.assert_called_once_with(scan_id)


def test_get_scan_status_returns_not_found_for_missing_database_row(client, auth_headers, monkeypatch):
    """Missing persisted scan state should return 404 instead of consulting memory."""
    monkeypatch.setenv("DATABASE_URL", "postgresql://ci:ci@localhost/ci_db")
    scan_id = "33333333-3333-3333-3333-333333333333"
    mock_db = MagicMock()
    mock_db.get_scan.return_value = None

    with patch("api.routes.scans.DatabaseManager", return_value=mock_db):
        resp = client.get(f"/api/scans/{scan_id}", headers=auth_headers)

    assert resp.status_code == 404
    assert resp.get_json() == {"error": "Scan not found"}
    mock_db.get_scan.assert_called_once_with(scan_id)


def test_claim_next_pending_scan_increments_attempt_count():
    """Claiming a pending scan should record a durable execution attempt."""
    db = DatabaseManager.__new__(DatabaseManager)
    scan_id = "44444444-4444-4444-4444-444444444444"
    cursor = _Cursor(rows=[{"scan_id": scan_id, "attempt_count": 1}])
    conn = MagicMock()
    conn.cursor.return_value = cursor

    with patch.object(db, "_get_conn", return_value=conn):
        scan = db.claim_next_pending_scan()

    executed_sql = cursor.calls[0][0]
    assert "attempt_count = COALESCE(attempt_count, 0) + 1" in executed_sql
    assert "error_message = NULL" in executed_sql
    assert scan["scan_id"] == scan_id
    conn.commit.assert_called_once()


def test_recover_stale_scans_retries_before_max_attempts():
    """Stale running scans should return to pending while attempts remain."""
    db = DatabaseManager.__new__(DatabaseManager)
    cursor = _Cursor(rowcounts=[0, 1])
    conn = MagicMock()
    conn.cursor.return_value = cursor

    with patch.object(db, "_get_conn", return_value=conn):
        recovered = db.recover_stale_scans(timeout_minutes=15, max_attempts=3)

    failed_sql, failed_params = cursor.calls[0]
    retry_sql, retry_params = cursor.calls[1]
    assert "status = 'failed'" in failed_sql
    assert failed_params == (3, 15)
    assert "status = 'pending'" in retry_sql
    assert "claimed_at = NULL" in retry_sql
    assert retry_params == (3, 15)
    assert recovered == 1
    conn.commit.assert_called_once()


def test_recover_stale_scans_fails_after_max_attempts():
    """Stale scans at the attempt limit should fail instead of retrying forever."""
    db = DatabaseManager.__new__(DatabaseManager)
    cursor = _Cursor(rowcounts=[1, 0])
    conn = MagicMock()
    conn.cursor.return_value = cursor

    with patch.object(db, "_get_conn", return_value=conn):
        recovered = db.recover_stale_scans(timeout_minutes=60, max_attempts=3)

    failed_sql, failed_params = cursor.calls[0]
    retry_sql, retry_params = cursor.calls[1]
    assert "COALESCE(attempt_count, 1) >= %s" in failed_sql
    assert failed_params == (3, 60)
    assert "COALESCE(attempt_count, 0) < %s" in retry_sql
    assert retry_params == (3, 60)
    assert recovered == 1
    conn.commit.assert_called_once()
