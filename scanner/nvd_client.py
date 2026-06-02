"""
scanner/nvd_client.py

MITRE NVD API client for OpenShield.

NVD public API: https://services.nvd.nist.gov/rest/json/cves/2.0
No API key required for basic use.
Rate limit (unauthenticated): 5 requests per 30 seconds.

Design decisions:
- In-memory cache keyed by search keyword to avoid duplicate NVD calls
  for the same resource type within one scan run.
- Enforces a 7-second gap between requests to stay under the rate limit.
- Retries on 429 (rate limited) with escalating back-off.
- All exceptions are caught here. Callers always receive a list - empty
  on failure - and never see an exception from this module.
"""

import time
import logging
import urllib.request
import urllib.error
import urllib.parse
import json
from typing import Optional

logger = logging.getLogger(__name__)

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_REQUEST_DELAY_SECONDS = 7.0   # Stay under 5 req/30 sec limit
_MAX_RETRIES = 3
_RESULTS_PER_PAGE = 5          # Top 5 CVEs per finding is enough for display

# In-memory cache. Keyed by "keyword:results_per_page".
# Resets each process - intentional, NVD data changes slowly.
_cache: dict[str, list[dict]] = {}
_last_request_time: float = 0.0


def _wait_for_rate_limit() -> None:
    """Sleep until the minimum gap between NVD requests has elapsed."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < _REQUEST_DELAY_SECONDS:
        time.sleep(_REQUEST_DELAY_SECONDS - elapsed)
    _last_request_time = time.time()


def _parse_cve_item(item: dict) -> Optional[dict]:
    """
    Extract the fields OpenShield needs from one NVD CVE item.

    NVD v2.0 response structure:
    {
      "cve": {
        "id": "CVE-2023-XXXXX",
        "descriptions": [{"lang": "en", "value": "..."}],
        "metrics": {
          "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
          "cvssMetricV30": [...],   # fallback if V31 absent
          "cvssMetricV2":  [...]    # older CVEs only
        },
        "cisaExploitAdd": "2023-01-01"  # present only if in CISA KEV catalogue
      }
    }

    Returns None if the item is malformed.
    """
    try:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Prefer English description
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available",
        )

        # CVSS score: try v3.1, then v3.0, then v2
        metrics = cve.get("metrics", {})
        cvss_score: Optional[float] = None
        cvss_severity: Optional[str] = None

        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_severity = cvss_data.get("baseSeverity")
                break

        # exploit_available: True if the CVE is in CISA's Known Exploited
        # Vulnerabilities catalogue (more reliable than vendor-reported status)
        exploit_available = "cisaExploitAdd" in cve

        return {
            "cve_id": cve_id,
            "description": description[:300],  # Truncate for DB storage
            "cvss_score": cvss_score,
            "cvss_severity": cvss_severity,
            "exploit_available": exploit_available,
            "nvd_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        }
    except Exception as e:
        logger.warning("Failed to parse CVE item: %s", e)
        return None


def query_nvd(keyword: str, results_per_page: int = _RESULTS_PER_PAGE) -> list[dict]:
    """
    Query NVD for CVEs matching a keyword.

    Returns a list of parsed CVE dicts (may be empty).
    Never raises - all failures return [].

    Args:
        keyword: Search term, e.g. "Azure Storage Account"
        results_per_page: Max CVEs to fetch (default 5)
    """
    cache_key = f"{keyword}:{results_per_page}"
    if cache_key in _cache:
        logger.debug("NVD cache hit for: %s", keyword)
        return _cache[cache_key]

    params = urllib.parse.urlencode({
        "keywordSearch": keyword,
        "resultsPerPage": results_per_page,
    })
    url = f"{_NVD_BASE_URL}?{params}"

    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            _wait_for_rate_limit()
            logger.debug("NVD query (attempt %d): %s", attempt, keyword)

            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "OpenShield/0.1 (github.com/openshield-org/openshield)"
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())

            vulnerabilities = data.get("vulnerabilities", [])
            results = [
                parsed
                for item in vulnerabilities
                if (parsed := _parse_cve_item(item)) is not None
            ]

            _cache[cache_key] = results
            logger.info("NVD returned %d CVEs for: %s", len(results), keyword)
            return results

        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 30 * attempt  # Back off harder each retry
                logger.warning(
                    "NVD rate limited (429). Waiting %ds before retry %d/%d",
                    wait, attempt, _MAX_RETRIES,
                )
                time.sleep(wait)
            else:
                logger.warning(
                    "NVD HTTP %d for keyword '%s': %s", e.code, keyword, e
                )
                break  # Non-rate-limit HTTP errors won't improve on retry

        except Exception as e:
            logger.warning(
                "NVD query failed (attempt %d/%d) for '%s': %s",
                attempt, _MAX_RETRIES, keyword, e,
            )
            if attempt < _MAX_RETRIES:
                time.sleep(2 ** attempt)

    logger.warning("NVD lookup failed for '%s' - returning empty list", keyword)
    _cache[cache_key] = []  # Cache the failure to avoid hammering NVD
    return []
