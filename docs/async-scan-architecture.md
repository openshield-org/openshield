# Asynchronous Scan Architecture

## Overview

OpenShield uses an asynchronous execution model for Azure posture scans. This architecture ensures the system can handle large subscriptions with thousands of resources without hitting web server timeouts or degrading frontend performance.

## The Problem: Synchronous Bottlenecks

In the legacy synchronous model, POST /api/scans/trigger would block the HTTP request until the scan completed. For large environments, this led to several critical issues. First, Gunicorn or load balancer timeouts would kill the scan mid execution. Second, web workers were tied up for minutes, preventing other users from accessing the dashboard. Third, the UI would hang or show generic Network Error messages while waiting for the response.

## The Solution: DB Backed Background Worker

OpenShield now employs a decoupled, database backed worker architecture. This is the industry standard for long running security tasks where reliability and state persistence are critical.

### 1. The API (Flask)
When a scan is triggered, the API performs minimal work. It validates the subscription_id, creates a record in the scans table with status set to pending, and returns 202 Accepted and the scan_id immediately.

### 2. The Queue (PostgreSQL)
The scans table acts as a persistent task queue. This avoids the need for additional infrastructure like Redis or RabbitMQ while providing ACID compliance, visibility, and auditability. Scan states are never lost during crashes, status polling is a simple SQL query, and every scan has a persistent record of its error state.

### 3. The Worker (Python)
The scanner/worker.py process runs independently of the web server. Its lifecycle involves several steps. It queries the DB for scans where status is pending. It updates the status to running to prevent other workers from picking it up. It invokes ScanEngine.run_scan(scan_id). On success, it saves findings and sets status to completed. On failure, it captures the traceback and sets status to failed with the error_message.

## Technical Rationale

### Why not Celery or Redis
While Celery is powerful, it introduces external dependencies and operational complexity. CSPM scans are macro tasks taking minutes rather than milliseconds. A database backed model is more resilient for these workloads because the state is persisted at the source of truth in PostgreSQL.

### Why not Threading
Python background threads are ephemeral. If the web server process restarts, all in flight scans are killed instantly and marked as running forever in the DB. A separate worker process ensures that the scan lifecycle is independent of the web server lifecycle.

## Testing Suite

The asynchronous transition is verified through a multi layered testing strategy.

### 1. Unit Tests
Located in tests/test_cve_correlator.py, tests/test_nvd_client.py, and tests/test_worker.py. These tests verify the core logic in isolation by mocking all network calls to Azure and NVD.

### 2. Smoke Tests
Located in tests/smoke_test.py. These tests verify the full integration. TC 13 verifies POST /api/scans/trigger returns 202 Accepted. TC 14 verifies the response contains a valid scan_id. TC 40 verifies that GET /api/scans/scan_id returns a valid status object, enabling frontend polling.

### 3. CI Validation
The ci checks job in .github/workflows/ci.yml ensures that worker syntax is valid, new database methods maintain schema integrity, and cross references between compliance mappings and rule files remain intact.

## Integrating with the Frontend

The frontend should follow this pattern for a smooth user experience. Call POST /api/scans/trigger. Extract the scan_id. Show a Scan Queued notification. Poll GET /api/scans/scan_id every 5 to 10 seconds until status is completed or failed. Refresh the dashboard once the status is completed.
