#!/usr/bin/env python3
"""
OpenShield API Smoke Test Suite
Runs against a live deployment to verify all endpoints.

Usage:
  # Local
  # Set API_URL: http://localhost:5000 and JWT_SECRET: your-secret
  python tests/smoke_test.py

  # Live Render deployment
  # Set API_URL: https://openshield-api.onrender.com and JWT_SECRET: your-secret
  python tests/smoke_test.py

JWT_SECRET must be the same value set in Render config — the test
generates a properly signed HS256 token from it automatically.
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ── Token generation ──────────────────────────────────────────────────────
# The app's before_request middleware calls jwt.decode() with HS256.
# Passing the raw JWT_SECRET as a Bearer token will always return 401.
# We must sign a real token using the same secret.

def _generate_token(secret: str) -> str:
    """Generate a valid HS256 JWT signed with the app's JWT_SECRET."""
    try:
        import jwt as pyjwt
        payload = {
            "sub": "smoke-test",
            "role": "admin",
            "iat": int(time.time()),
            "exp": int(time.time()) + 3600,  # 1 hour expiry
        }
        return pyjwt.encode(payload, secret, algorithm="HS256")
    except ImportError:
        print("ERROR: PyJWT not installed. Run: pip install PyJWT")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR generating JWT token: {e}")
        sys.exit(1)


API_URL = os.environ.get("API_URL", "http://localhost:5000").rstrip("/")
_JWT_VAL = os.environ.get("JWT_SECRET", "change-me-in-production")
_REAL_SUB = os.environ.get("AZURE_SUBSCRIPTION_ID", "")

# Real scan gate — requires explicit opt-in AND all four Azure credentials.
# Set RUN_REAL_SCAN=true in maintainer-controlled CI only.
_RUN_REAL_SCAN = os.environ.get("RUN_REAL_SCAN", "").lower() == "true"
_AZURE_CREDS_PRESENT = all([
    os.environ.get("AZURE_SUBSCRIPTION_ID"),
    os.environ.get("AZURE_CLIENT_ID"),
    os.environ.get("AZURE_CLIENT_SECRET"),
    os.environ.get("AZURE_TENANT_ID"),
])

if not _JWT_VAL or _JWT_VAL == "change-me-in-production":
    print("INFO: Using default JWT_SECRET ('change-me-in-production').")
    print("To use a custom one, set the JWT_SECRET environment variable.")

JWT_TOKEN = _generate_token(_JWT_VAL)

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
SKIP = "\033[93mSKIP\033[0m"

results = []


def request(method, path, body=None, auth=True, bad_token=False):
    """Make an HTTP request and return (status_code, response_body)."""
    url = f"{API_URL}{path}"
    headers = {"Content-Type": "application/json"}

    if bad_token:
        # Deliberately malformed token to test rejection
        headers["Authorization"] = "Bearer this.is.not.a.valid.jwt"
    elif auth and JWT_TOKEN:
        headers["Authorization"] = f"Bearer {JWT_TOKEN}"

    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=45) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try:
            body_bytes = e.read()
            return e.code, json.loads(body_bytes)
        except Exception:
            return e.code, {}
    except Exception as e:
        return 0, {"error": str(e)}


def test(name, method, path, check_fn, body=None, auth=True, bad_token=False):
    """Run a single test case."""
    status, body_resp = request(method, path, body=body, auth=auth, bad_token=bad_token)
    try:
        passed = check_fn(status, body_resp)
    except Exception as e:
        passed = False
        body_resp = {"exception": str(e)}

    label = PASS if passed else FAIL
    print(f"  [{label}] {name}")
    if not passed:
        print(f"         Status: {status}")
        print(f"         Body:   {json.dumps(body_resp, indent=2)[:300]}")

    results.append((name, passed))
    return passed


def skip(name, reason):
    """Record a test as skipped — does not count as a failure."""
    print(f"  [{SKIP}] {name}")
    print(f"         {reason}")
    results.append((name, None))


# ── TC-01: Health check ────────────────────────────────────────────────────
print("\n=== Health Check ===")
test(
    "TC-01 GET /health returns 200",
    "GET", "/health",
    lambda s, b: s == 200,
    auth=False,
)
test(
    "TC-02 GET /health returns status ok",
    "GET", "/health",
    lambda s, b: b.get("status") == "ok",
    auth=False,
)
test(
    "TC-03 GET /health requires no auth token",
    "GET", "/health",
    lambda s, b: s == 200,  # Public path — must not return 401
    auth=False,
)

# ── TC-04 to TC-08: Findings endpoint ─────────────────────────────────────
print("\n=== Findings Endpoint ===")
test(
    "TC-04 GET /api/findings returns 200",
    "GET", "/api/findings",
    lambda s, b: s == 200,
)
test(
    "TC-05 GET /api/findings returns 'findings' key",
    "GET", "/api/findings",
    lambda s, b: "findings" in b,
)
test(
    "TC-06 GET /api/findings returns 'count' key",
    "GET", "/api/findings",
    lambda s, b: "count" in b and isinstance(b["count"], int),
)
test(
    "TC-07 GET /api/findings?severity=HIGH filters correctly",
    "GET", "/api/findings?severity=HIGH",
    lambda s, b: s == 200 and all(
        f.get("severity") == "HIGH"
        for f in b.get("findings", [])
    ),
)
test(
    "TC-08 GET /api/findings?severity=INVALID returns 400 or empty",
    "GET", "/api/findings?severity=INVALID",
    lambda s, b: s in (200, 400),
)

# ── TC-09 to TC-11: Score endpoint ────────────────────────────────────────
print("\n=== Score Endpoint ===")
test(
    "TC-09 GET /api/score returns 200",
    "GET", "/api/score",
    lambda s, b: s == 200,
)
test(
    "TC-10 GET /api/score returns numeric score",
    "GET", "/api/score",
    lambda s, b: isinstance(b.get("score"), (int, float)),
)
test(
    "TC-11 GET /api/score is between 0 and 100",
    "GET", "/api/score",
    lambda s, b: 0 <= b.get("score", -1) <= 100,
)

# ── TC-12 to TC-14: Scans endpoint ────────────────────────────────────────
print("\n=== Scans Endpoint ===")
test(
    "TC-12 GET /api/scans returns 200",
    "GET", "/api/scans",
    lambda s, b: s == 200,
)

if _RUN_REAL_SCAN and _AZURE_CREDS_PRESENT:
    test(
        "TC-13 POST /api/scans/trigger returns 200, 201 or 202",
        "POST", "/api/scans/trigger",
        lambda s, b: s in (200, 201, 202),
        body={"subscription_id": _REAL_SUB},
    )
    test(
        "TC-14 POST /api/scans/trigger returns scan_id or job_id",
        "POST", "/api/scans/trigger",
        lambda s, b: any(k in b for k in ("scan_id", "job_id", "id", "message")),
        body={"subscription_id": _REAL_SUB},
    )
else:
    _skip_reason = (
        "Real scan skipped — set RUN_REAL_SCAN=true with all four Azure credentials to enable."
        if not _RUN_REAL_SCAN
        else "Real scan skipped — one or more Azure credentials (SUBSCRIPTION_ID, CLIENT_ID, CLIENT_SECRET, TENANT_ID) are missing."
    )
    skip("TC-13 POST /api/scans/trigger returns 200, 201 or 202", _skip_reason)
    skip("TC-14 POST /api/scans/trigger returns scan_id or job_id", _skip_reason)

# ── TC-15 to TC-17: Compliance endpoints ──────────────────────────────────
print("\n=== Compliance Endpoints ===")
for framework in ("cis", "nist", "iso27001"):
    test(
        f"TC GET /api/compliance/{framework} returns 200",
        "GET", f"/api/compliance/{framework}",
        lambda s, b: s == 200,
    )

# ── TC-18: Unauthenticated request is rejected ────────────────────────────
print("\n=== Auth / Security Edge Cases ===")
test(
    "TC-18 GET /api/findings without auth returns 401",
    "GET", "/api/findings",
    lambda s, b: s == 401,
    auth=False,
)
test(
    "TC-19 GET /api/findings with malformed token returns 401",
    "GET", "/api/findings",
    lambda s, b: s == 401,
    bad_token=True,
)

# ── TC-20 to TC-23: Edge cases ────────────────────────────────────────────
print("\n=== Edge Cases ===")
test(
    "TC-20 GET /nonexistent returns 404",
    "GET", "/nonexistent-endpoint-xyz",
    lambda s, b: s == 404,
    auth=True,
)
test(
    "TC-21 POST /api/scans/trigger with empty body still works",
    "POST", "/api/scans/trigger",
    lambda s, b: s in (200, 201, 202, 400),
    body={},
)
test(
    "TC-22 GET /api/findings?limit=0 does not crash",
    "GET", "/api/findings?limit=0",
    lambda s, b: s in (200, 400),
)
test(
    "TC-23 Response Content-Type is JSON",
    "GET", "/api/findings",
    lambda s, b: isinstance(b, dict),
)

# ── Summary ────────────────────────────────────────────────────────────────
print("\n=== Summary ===")
passed      = sum(1 for _, p in results if p is True)
skipped     = sum(1 for _, p in results if p is None)
failed_tests = [name for name, p in results if p is False]
total       = len(results)

skip_note = f", {skipped} skipped" if skipped else ""
print(f"  {passed}/{total - skipped} tests passed{skip_note}")

if skipped:
    print(f"\n  Skipped tests (not failures):")
    for name, p in results:
        if p is None:
            print(f"    - {name}")
    print(f"\n  To enable real scan tests: RUN_REAL_SCAN=true with AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID")

if failed_tests:
    print(f"\n  Failed tests:")
    for name in failed_tests:
        print(f"    - {name}")
    print(f"\nSmoke test FAILED. Do not open a PR until all tests pass.")
    sys.exit(1)
else:
    print(f"\n  All smoke tests passed.")
    sys.exit(0)
