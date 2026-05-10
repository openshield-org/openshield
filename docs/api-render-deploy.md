# Test Plan — API-DEP-001
# Render API Deployment and CI Smoke Testing
# ============================================================

## 1. Overview

This test plan covers the verification of the OpenShield API deployment 
to the Render free tier. The goal is to confirm:

- The Render Web Service builds and deploys the Flask app successfully.
- The database is automatically initialized on startup via `init_db`.
- The pre-commit hook and GitHub Actions CI pipeline gate the code properly.
- The CI pipeline is **community-friendly**, allowing forks to pass even without custom secrets.
- All 23 API edge cases (routing, filtering, authentication) function correctly in the live cloud environment.

---

## 2. Methodology and Test Rationale

To ensure the highest reliability of the deployment while accommodating free-tier constraints and community contributions, specific methods and test strategies were chosen:

### 2.1 Infrastructure and Pipeline Strategy
* **Targeting Render over Azure F1:** Azure App Service's F1 tier imposes a strict 60 CPU-minute daily cap. Render provides unmetered CPU on the free tier, making it significantly more reliable for demo and development environments.
* **Database Initialization:** The `api/models/finding.py` was updated with an `init_db` method. This method ensures that all required tables (`scans`, `findings`) are created automatically during the first deployment, preventing HTTP 500 errors.
* **Pre-commit Hook:** Fails fast. By running syntax checks and local API smoke tests *before* the commit is allowed, we prevent broken code from polluting the remote branch.
* **Community-Friendly CI Gate:** The GitHub Action is designed to be zero-friction for contributors.
    * **Optional Smoke Tests:** If `JWT_SECRET` is not set (typical for forks), the smoke test step is gracefully skipped rather than failing the build.
    * **Configurable URL:** The `API_URL` is configurable via GitHub Secrets/Variables, defaulting to the main production instance if not provided.

### 2.2 Token Generation Method
* **Dynamic HS256 Signing:** Instead of using a hardcoded dummy string, the test script dynamically generates a real token signed with the environment's `JWT_SECRET`.
* **Default Secret Alignment:** The smoke test defaults to `change-me-in-production`, matching the API's default. This allows tests to run "out of the box" in local environments without extra configuration.

> [!CAUTION]
> **ABSOLUTE SECURITY REQUIREMENT:** For any production deployment (Render, Azure, etc.), you **MUST** override the default `JWT_SECRET` with a long, random, and unique string. Leaving the default value in place makes your API vulnerable to unauthorized access via token forging.

### 2.3 API Smoke Test Strategy (The 23 Cases)
The 23 test cases were selected to prove the API is structurally sound and resilient:
* **Health Check (TC-01 to TC-03):** Confirms base app connectivity and ensures public routes are not locked.
* **Core Endpoints (TC-04 to TC-17):** Verifies the actual business logic and JSON structure.
* **Auth/Security (TC-18 to TC-19):** Confirms the JWT middleware is strictly enforced.
* **Edge Cases and Resilience (TC-20 to TC-23):** Ensures the app does not crash when given bad input or non-existent routes.

---

## 3. Files Under Test

| File | Purpose |
|---|---|
| `startup.sh` | Container startup script, DB initialization, and Gunicorn execution |
| `api/models/finding.py` | Added `init_db` to ensure schema existence on startup |
| `.github/workflows/deploy.yml` | Flexible GitHub Actions workflow (optional smoke tests) |
| `tests/smoke_test.py` | 23-case functional test suite with default secret support |
| `.git/hooks/pre-commit` | Local Git hook enforcing syntax checks and local smoke tests |

---

## 4. Test Environment Setup

### 4.1 Prerequisites
- Python 3.11 installed locally.
- Render account (render.com).
- OpenShield repository cloned locally.
- `.env` file populated locally with a valid `JWT_SECRET` and `DATABASE_URL`.
- Pre-commit hook installed locally (`chmod +x .git/hooks/pre-commit`).

### 4.2 Create Test Resources in Render
1.  **Render PostgreSQL Database (Free Tier)**
    - Name: `openshield-db`
2.  **Render Web Service (Free Tier)**
    - Connected to your branch.
    - Start Command: `./startup.sh`
    - Environment Variables set: `DATABASE_URL`, `JWT_SECRET`, `ALLOWED_ORIGINS`, `AZURE_SUBSCRIPTION_ID`.

---

## 5. Test Cases

### Part 1: Deployment & Pipeline Infrastructure

**DP-01 — Pre-commit hook enforces checks**
* **Steps:** Modify a file and run `git commit` with the local API turned off, then with it turned on.
* **Expected:** Blocks/warns when API is off; runs the 23-test suite and passes when API is on.

**DP-02 — Render executes startup script successfully**
* **Steps:** Push code to GitHub and monitor Render deployment logs.
* **Expected:** Logs show DB initialization (`Database initialized.`) and Gunicorn starting.

**DP-03 — GitHub Actions CI pipeline passes**
* **Steps:** Push a commit and monitor the GitHub Actions tab.
* **Expected:** 
    * **Main Repo:** Runs all 23 tests and passes.
    * **Forks:** Health gate may time out if Render isn't configured, but the workflow **will not fail**. It logs a skip message for smoke tests.

---

### Part 2: API Smoke Tests (Executed via `smoke_test.py`)

Run the following command against the live URL to execute these tests:
`API_URL=https://openshield-api.onrender.com JWT_SECRET=<secret> AZURE_SUBSCRIPTION_ID=<sub-id> python tests/smoke_test.py`

#### Health Check
* **TC-01:** GET `/health` returns HTTP 200.
* **TC-02:** GET `/health` returns JSON `{"status": "ok"}`.
* **TC-03:** GET `/health` requires no auth token (public route).

#### Findings Endpoint
* **TC-04:** GET `/api/findings` returns HTTP 200.
* **TC-05:** GET `/api/findings` returns a `findings` key in JSON.
* **TC-06:** GET `/api/findings` returns a numeric `count` key.
* **TC-07:** GET `/api/findings?severity=HIGH` correctly filters results.
* **TC-08:** GET `/api/findings?severity=INVALID` handles bad input safely (returns 200 or 400).

#### Score Endpoint
* **TC-09:** GET `/api/score` returns HTTP 200.
* **TC-10:** GET `/api/score` returns a numeric score.
* **TC-11:** GET `/api/score` ensures the score is mathematically between 0 and 100.

#### Scans Endpoint
* **TC-12:** GET `/api/scans` returns HTTP 200.
* **TC-13:** POST `/api/scans/trigger` returns HTTP 200, 201, or 202.
* **TC-14:** POST `/api/scans/trigger` returns a `scan_id` or `job_id`.

#### Compliance Endpoints
* **TC-15:** GET `/api/compliance/cis` returns HTTP 200.
* **TC-16:** GET `/api/compliance/nist` returns HTTP 200.
* **TC-17:** GET `/api/compliance/iso27001` returns HTTP 200.

#### Auth & Security Edge Cases
* **TC-18:** GET `/api/findings` without any auth header returns HTTP 401.
* **TC-19:** GET `/api/findings` with a malformed JWT returns HTTP 401.

#### General Edge Cases
* **TC-20:** GET `/nonexistent-endpoint-xyz` returns HTTP 404 (requires auth to pass middleware).
* **TC-21:** POST `/api/scans/trigger` with an empty JSON body still handles the request gracefully (returns success 201).
* **TC-22:** GET `/api/findings?limit=0` does not crash the server.
* **TC-23:** All valid endpoint responses include the `application/json` Content-Type.

---

## 6. Cleanup

Render Free Tier Web Services spin down after 15 minutes of inactivity. The Free PostgreSQL database will automatically be deleted by Render after 90 days. To clean up manually, delete both resources from the Render dashboard Settings page.

---

## 7. Pass / Fail Summary Table

| Test Case | Description | Expected | Status |
|---|---|---|---|
| **DP-01** | Pre-commit Git hook functioning | Hook runs & enforces rules | [ ] |
| **DP-02** | Render deployment & startup | App goes Live & DB inits | [ ] |
| **DP-03** | GitHub Actions CI Pipeline | Workflow passes (Green) | [ ] |
| **TC-01** | `/health` returns 200 | Pass | [ ] |
| **TC-02** | `/health` returns status ok | Pass | [ ] |
| **TC-03** | `/health` requires no auth | Pass | [ ] |
| **TC-04** | `/api/findings` returns 200 | Pass | [ ] |
| **TC-05** | `/api/findings` returns findings key | Pass | [ ] |
| **TC-06** | `/api/findings` returns count key | Pass | [ ] |
| **TC-07** | `/api/findings` severity filter | Pass | [ ] |
| **TC-08** | `/api/findings` invalid severity | Pass | [ ] |
| **TC-09** | `/api/score` returns 200 | Pass | [ ] |
| **TC-10** | `/api/score` returns numeric | Pass | [ ] |
| **TC-11** | `/api/score` bounded 0-100 | Pass | [ ] |
| **TC-12** | `/api/scans` returns 200 | Pass | [ ] |
| **TC-13** | `/api/scans/trigger` works | 200, 201, or 202 | [ ] |
| **TC-14** | `/api/scans/trigger` returns ID | Pass | [ ] |
| **TC-15** | `/api/compliance/cis` works | Pass | [ ] |
| **TC-16** | `/api/compliance/nist` works | Pass | [ ] |
| **TC-17** | `/api/compliance/iso27001` works | Pass | [ ] |
| **TC-18** | Missing auth returns 401 | Pass | [ ] |
| **TC-19** | Bad token returns 401 | Pass | [ ] |
| **TC-20** | 404 routing works safely | Pass | [ ] |
| **TC-21** | Empty body payload handled | Pass (201) | [ ] |
| **TC-22** | Limit=0 query handled safely | Pass | [ ] |
| **TC-23** | Content-Type is JSON | Pass | [ ] |

All 26 checks (3 Pipeline + 23 API) must pass on the main repository before opening the PR.
