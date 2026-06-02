# OpenShield - CVE Correlation Feature Documentation

## Overview

The CVE Correlation feature integrates the MITRE National Vulnerability Database (NVD) API with the OpenShield scanner. It cross-references security misconfigurations discovered during scans with known Common Vulnerabilities and Exposures (CVEs), providing users with CVSS scores and exploit availability status.

## Files Created and Modified

### New Files (Core Logic)

| File | Purpose |
|---|---|
| scanner/nvd_client.py | NVD API Integration. Handles low-level communication with MITRE NVD. Implements strict rate-limiting (7s gap), in-memory caching for performance, and exponential back-off for reliability. |
| scanner/cve_correlator.py | Contextual Mapping. Maps OpenShield Rule IDs (e.g., AZ-STOR) to NVD search terms. Performs the logic of merging raw API results into finding objects. |
| tests/test_cve_correlator.py | Logic Verification. Unit tests ensuring Rule IDs map correctly and finding enrichment correctly identifies the highest risk. |

### Modified Files (Integration)

| File | Change | Why |
|---|---|---|
| scanner/engine.py | Enrichment-at-Source. Integrated enrich_findings directly into the scan lifecycle. | Performance: By enriching during the scan, CVE data is saved once to the database. The frontend does not have to wait for an NVD API call when loading the dashboard. |
| api/models/finding.py | Updated Finding dataclass and added run_migrations and get_cve_summary. | Persistence: Adds cve_references, cvss_score, and exploit_available columns to PostgreSQL. get_cve_summary provides stats for dashboard widgets. |
| api/app.py | Added db.run_migrations call at startup. | Auto-Deployment: Ensures the database schema is updated automatically on any environment where the app is launched. |
| api/routes/score.py | Added GET /api/score/cve-summary endpoint. | Dashboard UI: Provides the frontend with high-level data like Total Known Exploits in a single lightweight request. |
| api/routes/findings.py | Returns findings from the database and enriches only legacy rows missing CVE fields. | Performance: Avoids extra NVD calls on every request while still backfilling older records. |

## Frontend Integration Design

To ensure the frontend dashboard works perfectly, the architecture uses an Enrichment-at-Source model:

1. Zero-Latency Dashboard Loads: The scan engine pre-enriches findings. When the frontend calls the API, it receives static data from the database. Legacy rows missing CVE fields are enriched on-demand only once.
2. Dashboard-Ready Summary Endpoint: The /api/score/cve-summary endpoint allows the frontend to fetch high-level statistics (Total Findings, Exploit Count, Max CVSS) in one call instead of processing thousands of records locally.
3. Actionable Risk (CISA KEV): The exploit_available flag uses the CISA Known Exploited Vulnerabilities catalogue, allowing the dashboard to highlight high-priority risks that are being exploited in the wild.
4. Persistent Historical State: Enrichment happens at the time of scan, meaning the dashboard shows the CVE status as it existed on that day. This ensures accurate compliance and historical reporting.

## Security and Compliance Audit

1. No Hardcoded Secrets: All credentials (DATABASE_URL, JWT_SECRET) are handled via environment variables.
2. SSRF Protection: NVD query parameters are sanitized and derived from internal static maps.
3. SQL Safety: All database additions use parameterized queries to prevent injection.
4. Character Quality: All non-ASCII characters and emojis were removed for pipeline compatibility.

## Frontend-Ready API Responses

### GET /api/findings

Response shape (abridged):

```json
{
   "count": 2,
   "findings": [
      {
         "id": 123,
         "rule_id": "AZ-STOR-003",
         "severity": "HIGH",
         "resource_id": "/subscriptions/...",
         "cve_references": [
            {
               "cve_id": "CVE-2023-12345",
               "cvss_score": 9.8,
               "cvss_severity": "CRITICAL",
               "exploit_available": true,
               "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"
            }
         ],
         "cvss_score": 9.8,
         "exploit_available": true
      }
   ]
}
```

Notes:
1. Results are ordered by detected_at descending and capped at 1000.
2. CVE fields are always present. Legacy rows are backfilled on request.

### GET /api/score/cve-summary

Response shape:

```json
{
   "total_findings": 74,
   "exploit_count": 5,
   "max_cvss_score": 9.8,
   "avg_cvss_score": 6.42,
   "critical_cve_count": 3
}
```

## Testing Strategy

All logic is verified using the Python standard library unittest framework. All NVD HTTP calls are fully mocked to ensure stability.

### Testing Rationale

The tests focus on the correlator behavior with all NVD calls mocked:

1. Keyword Mapping (TestGetNvdKeyword):
   * Purpose: Ensure rule_id values resolve to a stable NVD keyword.
   * Rationale: Prefix fallback prevents gaps when new rules are added.

2. Enrichment Logic (TestEnrichSingleFinding, TestEnrichFindings):
   * Purpose: Validate cve_references, cvss_score, and exploit_available handling.
   * Rationale: Ensures highest CVSS is selected and output order is preserved.

### How to run the tests

```bash
python3 -m unittest tests/test_cve_correlator.py -v
```

Expected output: All tests passing, zero network calls made.
