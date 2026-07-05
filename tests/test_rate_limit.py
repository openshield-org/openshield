"""Tests for api.rate_limit.rate_limit (SEC-004)."""

import pytest
from flask import Flask, jsonify

from api.rate_limit import _hits, rate_limit


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    _hits.clear()
    yield
    _hits.clear()


def _make_app(limit=3, window=60):
    app = Flask(__name__)

    @app.get("/ping")
    @rate_limit(limit, window)
    def ping():
        return jsonify({"ok": True})

    return app


def test_requests_under_limit_succeed():
    client = _make_app(limit=3).test_client()
    for _ in range(3):
        assert client.get("/ping").status_code == 200


def test_requests_over_limit_are_rejected():
    client = _make_app(limit=3).test_client()
    for _ in range(3):
        client.get("/ping")
    resp = client.get("/ping")
    assert resp.status_code == 429


def test_limit_is_scoped_per_route():
    app = Flask(__name__)

    @app.get("/a")
    @rate_limit(1)
    def a():
        return jsonify({"ok": True})

    @app.get("/b")
    @rate_limit(1)
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
