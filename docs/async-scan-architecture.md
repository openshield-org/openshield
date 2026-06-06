# Asynchronous Scan Architecture

## Overview

OpenShield uses an asynchronous execution model for Azure posture scans. This architecture ensures the system can handle large subscriptions with thousands of resources without hitting web server timeouts or degrading frontend performance.

## The Problem: Synchronous Bottlenecks

In the legacy synchronous model, `POST /api/scans/trigger` would block the HTTP request until the scan completed. For large environments, this led to:
1. **API Timeouts:** Gunicorn or load balancer timeouts (typically 30-60s) would kill the scan mid-execution.
2. **Resource Exhaustion:** Web workers were tied up for minutes, preventing other users from accessing the dashboard.
3. **Frontend Fragility:** The UI would hang or show generic "Network Error" messages while waiting for the response.

## The Solution: DB-Backed Background Worker

OpenShield now employs a decoupled, database-backed worker architecture. This is the industry standard for long-running security tasks where reliability and state persistence are critical.

### 1. The API (Flask)
When a scan is triggered, the API performs minimal work:
- Validates the `subscription_id`.
- Creates a record in the `scans` table with `status = 'pending'`.
- Returns `202 Accepted` and the `scan_id` immediately.

### 2. The Queue (PostgreSQL)
The `scans` table acts as a persistent task queue. This avoids the need for additional infrastructure like Redis or RabbitMQ while providing:
- **ACID Compliance:** Scan states are never lost, even during crashes.
- **Visibility:** Status polling is a simple SQL query.
- **Auditability:** Every scan, including those that fail, has a persistent record of its error state.

### 3. The Worker (Python)
The `scanner/worker.py` process runs independently of the web server. Its lifecycle is:
1. **Poll:** Query the DB for scans where `status = 'pending'`.
2. **Claim:** Update the status to `running` to prevent other workers (in a multi-node setup) from picking it up.
3. **Execute:** Invoke `ScanEngine.run_scan(scan_id)`.
4. **Finalize:** 
   - On success: Save findings and set `status = 'completed'`.
   - On failure: Capture the traceback and set `status = 'failed'` with the `error_message`.

---

## Technical Rationale

### Why not Celery/Redis?
While Celery is powerful, it introduces external dependencies and operational complexity. CSPM scans are "macro-tasks" (taking minutes, not milliseconds). A database-backed model is more resilient for these workloads because the state is persisted at the source of truth (PostgreSQL).

### Why not Threading?
Python background threads (`threading.Thread`) are ephemeral. If the web server process restarts (common in cloud environments like Render or Heroku), all in-flight scans are killed instantly and marked as "running" forever in the DB. A separate worker process ensures that the scan lifecycle is independent of the web server lifecycle.

---

## Testing Suite

The asynchronous transition is verified through a multi-layered testing strategy.

### 1. Unit Tests
Located in `tests/test_cve_correlator.py` and `tests/test_nvd_client.py`. These tests verify the core logic in isolation by mocking all network calls (Azure and NVD). 

### 2. Smoke Tests
Located in `tests/smoke_test.py`. These tests verify the full integration:
- **TC-13:** Verifies `POST /api/scans/trigger` returns `202 Accepted`.
- **TC-14:** Verifies the response contains a valid `scan_id`.
- **TC-40:** Verifies that `GET /api/scans/<scan_id>` returns a valid status object, enabling frontend polling.

### 3. CI Validation
The `ci-checks` job in `.github/workflows/ci.yml` ensures that:
- The worker syntax is valid.
- The new database methods maintain schema integrity.
- Cross-references between compliance mappings and rule files remain intact.

---

## Integrating with the Frontend

The frontend should follow this pattern for a smooth user experience:
1. Call `POST /api/scans/trigger`.
2. Extract the `scan_id`.
3. Show a "Scan Queued" notification.
4. Poll `GET /api/scans/<scan_id>` every 5-10 seconds until `status` is `completed` or `failed`.
5. Refresh the dashboard once the status is `completed`.
