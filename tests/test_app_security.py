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
