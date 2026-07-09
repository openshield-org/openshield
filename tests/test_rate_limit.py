"""Tests for api.rate_limit.rate_limit (SEC-004)."""

from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, jsonify

import api.rate_limit as rate_limit_module


class _FakeRateLimitStore:
    """In-memory stand-in for the rate_limit_hits table, keyed like Postgres.

    Mimics the real query sequence in _check_and_record: purge expired
    hits for the key, count what's left, and only record a new hit when
    under the limit — so the decorator's behavior is exercised without a
    live database.
    """

    def __init__(self):
        self.hits: dict[str, list[float]] = {}

    def check_and_record(self, key: str, max_requests: int, window_seconds: int) -> bool:
        recent = self.hits.get(key, [])
        if len(recent) >= max_requests:
            return False
        recent.append(0.0)
        self.hits[key] = recent
        return True


@pytest.fixture
def _mock_db_backend(monkeypatch):
    """Stand in for the Postgres-backed store at the decorator level.

    Applied explicitly (not autouse) so the low-level tests further down
    that exercise the real _check_and_record's SQL can still call the
    genuine implementation. Sets DATABASE_URL so the decorator's
    config-guard doesn't short-circuit to the 503 path before reaching
    _check_and_record.
    """
    monkeypatch.setenv("DATABASE_URL", "postgresql://test/db")
    store = _FakeRateLimitStore()
    with patch.object(rate_limit_module, "_check_and_record", side_effect=store.check_and_record):
        yield store


def _make_app(limit=3, window=60):
    app = Flask(__name__)

    @app.get("/ping")
    @rate_limit_module.rate_limit(limit, window)
    def ping():
        return jsonify({"ok": True})

    return app


def test_requests_under_limit_succeed(_mock_db_backend):
    client = _make_app(limit=3).test_client()
    for _ in range(3):
        assert client.get("/ping").status_code == 200


def test_requests_over_limit_are_rejected(_mock_db_backend):
    client = _make_app(limit=3).test_client()
    for _ in range(3):
        client.get("/ping")
    resp = client.get("/ping")
    assert resp.status_code == 429


def test_limit_is_scoped_per_route(_mock_db_backend):
    app = Flask(__name__)

    @app.get("/a")
    @rate_limit_module.rate_limit(1)
    def a():
        return jsonify({"ok": True})

    @app.get("/b")
    @rate_limit_module.rate_limit(1)
    def b():
        return jsonify({"ok": True})

    client = app.test_client()
    assert client.get("/a").status_code == 200
    assert client.get("/b").status_code == 200
    assert client.get("/a").status_code == 429


def test_testing_mode_bypasses_rate_limit():
    app = _make_app(limit=1)
    app.config["TESTING"] = True
    client = app.test_client()
    for _ in range(5):
        assert client.get("/ping").status_code == 200


def test_missing_database_url_returns_503_instead_of_silently_disabling(monkeypatch):
    """Unlike a transient DB error (which fails open), a deployment that's
    simply missing DATABASE_URL must not silently run this metered endpoint
    with no rate limiting for its entire lifetime — it should refuse loudly."""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    app = _make_app(limit=1)
    client = app.test_client()

    resp = client.get("/ping")

    assert resp.status_code == 503


def test_check_failure_fails_open(_mock_db_backend):
    """A DB error during the rate-limit check must not block the request —
    this limiter blunts abuse, it isn't the endpoint's primary safeguard."""
    app = _make_app(limit=1)
    client = app.test_client()

    with patch.object(rate_limit_module, "_check_and_record", side_effect=Exception("db down")):
        assert client.get("/ping").status_code == 200
        assert client.get("/ping").status_code == 200


def test_check_and_record_uses_advisory_lock_and_purges_expired_hits():
    """Verify the real _check_and_record issues the expected Postgres calls:
    advisory lock, purge-then-count, and insert only when under the limit."""
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (0,)
    mock_cursor.__enter__.return_value = mock_cursor
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_db = MagicMock()
    mock_db._get_conn.return_value = mock_conn

    with patch.object(rate_limit_module, "_get_db", return_value=mock_db):
        allowed = rate_limit_module._check_and_record("1.2.3.4:/api/x", 5, 60)

    assert allowed is True
    queries = [call.args[0] for call in mock_cursor.execute.call_args_list]
    assert any("pg_advisory_xact_lock" in q for q in queries)
    assert any("DELETE FROM rate_limit_hits" in q for q in queries)
    assert any("SELECT COUNT(*) FROM rate_limit_hits" in q for q in queries)
    assert any("INSERT INTO rate_limit_hits" in q for q in queries)
    mock_conn.commit.assert_called_once()


def test_check_and_record_denies_and_skips_insert_when_at_limit():
    mock_cursor = MagicMock()
    mock_cursor.fetchone.return_value = (5,)
    mock_cursor.__enter__.return_value = mock_cursor
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_db = MagicMock()
    mock_db._get_conn.return_value = mock_conn

    with patch.object(rate_limit_module, "_get_db", return_value=mock_db):
        allowed = rate_limit_module._check_and_record("1.2.3.4:/api/x", 5, 60)

    assert allowed is False
    queries = [call.args[0] for call in mock_cursor.execute.call_args_list]
    assert not any("INSERT INTO rate_limit_hits" in q for q in queries)
    mock_conn.commit.assert_called_once()


def test_check_and_record_rolls_back_on_query_error():
    """A mid-transaction error must roll back rather than leave the
    connection in an aborted-transaction state for later use."""
    mock_cursor = MagicMock()
    mock_cursor.__enter__.return_value = mock_cursor
    mock_cursor.execute.side_effect = [None, None, Exception("lock timeout")]
    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_db = MagicMock()
    mock_db._get_conn.return_value = mock_conn

    with patch.object(rate_limit_module, "_get_db", return_value=mock_db):
        with pytest.raises(Exception, match="lock timeout"):
            rate_limit_module._check_and_record("1.2.3.4:/api/x", 5, 60)

    mock_conn.rollback.assert_called_once()
    mock_conn.commit.assert_not_called()
