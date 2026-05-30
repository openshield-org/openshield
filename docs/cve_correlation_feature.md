# OpenShield - CVE Correlation Feature Documentation

## Overview

The CVE Correlation feature integrates the MITRE National Vulnerability Database (NVD) API with the OpenShield scanner. It cross-references security misconfigurations discovered during scans with known Common Vulnerabilities and Exposures (CVEs), providing users with CVSS scores and exploit availability status.

## Files Created and Modified

### New Files (Core Logic)

| File | Purpose |
|---|---|
| scanner/nvd_client.py | NVD API Integration. Handles low-level communication with MITRE NVD. Implements strict rate-limiting (7s gap), in-memory caching for performance, and exponential back-off for reliability. |
| scanner/cve_correlator.py | Contextual Mapping. Maps OpenShield Rule IDs (e.g., AZ-STOR) to NVD search terms. Performs the logic of merging raw API results into finding objects. |
| tests/test_nvd_client.py | Client Verification. Unit tests verifying parsing logic, 429 retry handling, and cache hits. |
| tests/test_cve_correlator.py | Logic Verification. Unit tests ensuring Rule IDs map correctly and finding enrichment correctly identifies the highest risk. |

### Modified Files (Integration)

| File | Change | Why |
|---|---|---|
| scanner/engine.py | Enrichment-at-Source. Integrated enrich_findings directly into the scan lifecycle. | Performance: By enriching during the scan, CVE data is saved once to the database. The frontend does not have to wait for an NVD API call when loading the dashboard. |
| api/models/finding.py | Updated Finding dataclass and added run_migrations and get_cve_summary. | Persistence: Adds cve_references, cvss_score, and exploit_available columns to PostgreSQL. get_cve_summary provides stats for dashboard widgets. |
| api/app.py | Added db.run_migrations call at startup. | Auto-Deployment: Ensures the database schema is updated automatically on any environment where the app is launched. |
| api/routes/score.py | Added GET /api/score/cve-summary endpoint. | Dashboard UI: Provides the frontend with high-level data like Total Known Exploits in a single lightweight request. |
| api/routes/findings.py | Adjusted list_findings to return data from the database. | Clean API: Keeps the API response structure consistent while including the new enriched security data. |

## Frontend Integration Design

To ensure the frontend dashboard works perfectly, the architecture uses an Enrichment-at-Source model:

1. Zero-Latency Dashboard Loads: The scan engine pre-enriches findings. When the frontend calls the API, it receives static data from the database. Response times are reduced from seconds to milliseconds.
2. Dashboard-Ready Summary Endpoint: The /api/score/cve-summary endpoint allows the frontend to fetch high-level statistics (Total Findings, Exploit Count, Max CVSS) in one call instead of processing thousands of records locally.
3. Actionable Risk (CISA KEV): The exploit_available flag uses the CISA Known Exploited Vulnerabilities catalogue, allowing the dashboard to highlight high-priority risks that are being exploited in the wild.
4. Persistent Historical State: Enrichment happens at the time of scan, meaning the dashboard shows the CVE status as it existed on that day. This ensures accurate compliance and historical reporting.

## Security and Compliance Audit

1. No Hardcoded Secrets: All credentials (DATABASE_URL, JWT_SECRET) are handled via environment variables.
2. SSRF Protection: NVD query parameters are sanitized and derived from internal static maps.
3. SQL Safety: All database additions use parameterized queries to prevent injection.
4. Character Quality: All non-ASCII characters and emojis were removed for pipeline compatibility.

## Testing Strategy

All logic is verified using the Python standard library unittest framework. All NVD HTTP calls are fully mocked to ensure stability.

### Testing Rationale

The 27 tests were selected to verify three critical areas of the API integration:

1. Data Integrity (TestParseConveItem):
   * Purpose: The NVD API response is deeply nested and contains multiple CVSS versions (v2, v3.0, v3.1).
   * Rationale: We must guarantee the scanner always extracts the highest precision score available. We also verify description truncation to ensure unexpectedly long CVE descriptions do not exceed database column limits.

2. System Stability (TestQueryNvd):
   * Purpose: To prevent the scanner from being rate-limited or banned by MITRE.
   * Rationale: We verify that the in-memory cache is used for repeated resource types. We also simulate 429 (Rate Limited) responses to confirm the exponential back-off logic works. Finally, we ensure that network failures return an empty list instead of raising exceptions, keeping the core scanner operational.

3. Logic Correctness (TestGetNvdKeyword and TestEnrichFindings):
   * Purpose: To verify the mapping engine and risk calculation.
   * Rationale: We test the prefix-fallback mechanism to ensure the feature is future-proof for new rules. We also verify that when multiple CVEs match, the highest CVSS score is selected to highlight the maximum risk on the dashboard.

4. Integration Safety (TestEnrichSingleFinding):
   * Purpose: To ensure enrichment is non-destructive.
   * Rationale: We verify that adding CVE data does not overwrite existing scanner fields like resource_id or base severity.

### How to run the tests

```bash
python3 -m unittest tests/test_nvd_client.py tests/test_cve_correlator.py -v
```

Expected output: All tests passing, zero network calls made.
