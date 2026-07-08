"""Tests for the observability layer (issue #159).

Covers the liveness/readiness probes, the Prometheus /metrics endpoint,
request-ID propagation, request_id in auth-failure responses, and the
conditional Sentry initialisation.
"""

import uuid
from unittest.mock import MagicMock

import pytest

from api.app import create_app
from api.observability import SCANS_TOTAL, init_sentry


def _build_app(db_mock, monkeypatch):
    """Build a fresh app whose DatabaseManager is replaced by ``db_mock``."""
    monkeypatch.setattr("api.app.DatabaseManager", MagicMock(return_value=db_mock))
    app = create_app()
    app.config["TESTING"] = True
    return app


# --------------------------------------------------------------------------- #
# Liveness / readiness                                                         #
# --------------------------------------------------------------------------- #
def test_health_is_public_and_independent_of_db(monkeypatch):
    """/health must return 200 without ever touching the database."""
    failing_db = MagicMock()
    failing_db.ping.side_effect = Exception("db is down")
    app = _build_app(failing_db, monkeypatch)

    resp = app.test_client().get("/health")

    assert resp.status_code == 200
    assert resp.get_json() == {"status": "ok"}
    failing_db.ping.assert_not_called()


def test_ready_returns_200_when_db_reachable(monkeypatch):
    healthy_db = MagicMock()
    healthy_db.ping.return_value = True
    app = _build_app(healthy_db, monkeypatch)

    resp = app.test_client().get("/ready")

    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ready"
    healthy_db.ping.assert_called_once()


def test_ready_returns_503_when_db_unavailable(monkeypatch):
    failing_db = MagicMock()
    failing_db.ping.side_effect = Exception("connection refused")
    app = _build_app(failing_db, monkeypatch)

    resp = app.test_client().get("/ready")

    assert resp.status_code == 503
    assert resp.get_json() == {"status": "not_ready", "error": "database_unreachable"}


# --------------------------------------------------------------------------- #
# Prometheus metrics                                                           #
# --------------------------------------------------------------------------- #
def test_metrics_endpoint_returns_prometheus_text(client):
    resp = client.get("/metrics")

    assert resp.status_code == 200
    assert "text/plain" in resp.content_type
    body = resp.get_data(as_text=True)
    # A registered, unlabelled histogram is always emitted even at zero.
    assert "openshield_scan_duration_seconds" in body


# --------------------------------------------------------------------------- #
# Request IDs                                                                  #
# --------------------------------------------------------------------------- #
def test_client_supplied_request_id_is_echoed(client):
    supplied = "client-supplied-123"
    resp = client.get("/health", headers={"X-Request-ID": supplied})

    assert resp.headers.get("X-Request-ID") == supplied


def test_request_id_is_generated_when_missing(client):
    resp = client.get("/health")

    returned = resp.headers.get("X-Request-ID")
    assert returned
    # A generated ID is a valid UUID.
    uuid.UUID(returned)


def test_auth_failure_json_includes_request_id(client):
    # POST to a protected route without a Bearer token → 401 from JWT middleware.
    resp = client.post("/api/scans")

    assert resp.status_code == 401
    payload = resp.get_json()
    assert "request_id" in payload
    # The body request_id matches the echoed response header.
    assert payload["request_id"] == resp.headers.get("X-Request-ID")


# --------------------------------------------------------------------------- #
# Sentry                                                                       #
# --------------------------------------------------------------------------- #
def test_sentry_not_initialized_when_dsn_unset(monkeypatch):
    monkeypatch.delenv("SENTRY_DSN", raising=False)
    fake_init = MagicMock()
    monkeypatch.setattr("sentry_sdk.init", fake_init)

    assert init_sentry() is False
    fake_init.assert_not_called()


def test_sentry_initialized_when_dsn_set(monkeypatch):
    monkeypatch.setenv("SENTRY_DSN", "https://public@o0.ingest.sentry.io/1")
    fake_init = MagicMock()
    monkeypatch.setattr("sentry_sdk.init", fake_init)

    assert init_sentry() is True
    fake_init.assert_called_once()
    assert fake_init.call_args.kwargs["dsn"] == "https://public@o0.ingest.sentry.io/1"


# --------------------------------------------------------------------------- #
# Worker metrics do not break the worker                                       #
# --------------------------------------------------------------------------- #
def test_worker_records_scan_metrics_on_success(monkeypatch):
    """The worker's success path increments the completed scan counter."""
    from scanner import worker

    class _Stop(BaseException):
        pass

    scan_id = str(uuid.uuid4())
    sub_id = "00000000-0000-0000-0000-000000000000"

    mock_db = MagicMock()
    mock_db.recover_stale_scans.side_effect = [None, _Stop()]
    mock_db.claim_next_pending_scan.side_effect = [
        {"scan_id": scan_id, "subscription_id": sub_id},
        None,
    ]
    mock_engine = MagicMock()
    mock_engine.run_scan.return_value = {
        "scan_id": scan_id,
        "subscription_id": sub_id,
        "findings": [],
        "total_findings": 0,
        "started_at": "2026-01-01T00:00:00Z",
    }

    monkeypatch.setattr(worker, "DatabaseManager", MagicMock(return_value=mock_db))
    monkeypatch.setattr(worker, "ScanEngine", MagicMock(return_value=mock_engine))
    monkeypatch.setattr(worker.os.environ, "get", lambda *a, **k: "postgresql://x")
    monkeypatch.setattr(worker.time, "sleep", lambda *a, **k: None)

    before = SCANS_TOTAL.labels(status="completed")._value.get()
    with pytest.raises(_Stop):
        worker.run_worker()
    after = SCANS_TOTAL.labels(status="completed")._value.get()

    assert after == before + 1
    mock_db.save_scan.assert_called_once()
