"""App-level security tests: JWT enforcement on GET routes (SEC-001) and
request body size limits (SEC-002)."""


def test_get_score_without_auth_returns_401(client):
    resp = client.get("/api/score")
    assert resp.status_code == 401


def test_get_findings_without_auth_returns_401(client):
    resp = client.get("/api/findings")
    assert resp.status_code == 401


def test_get_scans_without_auth_returns_401(client):
    resp = client.get("/api/scans")
    assert resp.status_code == 401


def test_get_compliance_without_auth_returns_401(client):
    resp = client.get("/api/compliance/cis")
    assert resp.status_code == 401


def test_health_and_index_remain_public(client):
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200


def test_oversized_body_returns_413(client, auth_headers):
    large_body = b"a" * (3 * 1024 * 1024)  # 3 MB, over the 2 MB limit
    resp = client.post("/api/ai/insights", data=large_body, headers=auth_headers)
    assert resp.status_code == 413


def test_proxy_fix_trusts_exactly_one_hop(app):
    """Render terminates TLS and proxies to the app over one hop. Without
    ProxyFix, request.remote_addr is always Render's proxy address, which
    collapses every distinct client into one rate-limit bucket. Trusting
    more than one hop would let a client spoof its own IP via a forged
    leading X-Forwarded-For entry, so exactly one hop must be configured."""
    from werkzeug.middleware.proxy_fix import ProxyFix

    assert isinstance(app.wsgi_app, ProxyFix)
    assert app.wsgi_app.x_for == 1
    assert app.wsgi_app.x_proto == 1


def test_forwarded_for_resolves_through_full_wsgi_stack(app):
    """End-to-end: a request through the real WSGI stack (not
    test_request_context, which bypasses wsgi_app entirely) must see
    request.remote_addr rewritten from the trusted forwarded header."""
    import api.app as app_module

    app_module._ALWAYS_PUBLIC.add("/__debug_remote_addr")
    try:

        @app.route("/__debug_remote_addr")
        def _debug_remote_addr():
            from flask import jsonify, request

            return jsonify({"ip": request.remote_addr})

        client = app.test_client()
        resp = client.get(
            "/__debug_remote_addr",
            headers={"X-Forwarded-For": "203.0.113.7, 198.51.100.9"},
            environ_overrides={"REMOTE_ADDR": "10.0.0.1"},
        )
        assert resp.get_json()["ip"] == "198.51.100.9"
    finally:
        app_module._ALWAYS_PUBLIC.discard("/__debug_remote_addr")
