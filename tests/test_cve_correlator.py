"""
tests/test_cve_correlator.py

Unit tests for scanner/cve_correlator.py.

query_nvd() is patched in all tests so no live NVD calls are made.
The module-level NVD cache is cleared in setUp() to prevent cross-test
interference.

Test classes:
  TestGetNvdKeyword      - _get_nvd_keyword() mapping logic (no mocking)
  TestEnrichSingleFinding - _enrich_single_finding() CVE merging (mocked query_nvd)
  TestEnrichFindings     - enrich_findings() public API (mocked query_nvd)
"""

import unittest
from unittest.mock import patch

from scanner.nvd_client import _cache
from scanner.cve_correlator import (
    _get_nvd_keyword,
    _enrich_single_finding,
    enrich_findings,
)


# ---------------------------------------------------------------------------
# Shared fixture - one CVE returned by a mocked query_nvd call
# ---------------------------------------------------------------------------

_MOCK_CVE = {
    "cve_id": "CVE-2023-12345",
    "description": "A critical vulnerability in Azure Storage.",
    "cvss_score": 9.8,
    "cvss_severity": "CRITICAL",
    "exploit_available": True,
    "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
}

_MOCK_CVE_NO_EXPLOIT = {
    "cve_id": "CVE-2022-99999",
    "description": "Medium severity configuration issue.",
    "cvss_score": 5.4,
    "cvss_severity": "MEDIUM",
    "exploit_available": False,
    "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-99999",
}


# ---------------------------------------------------------------------------
# TestGetNvdKeyword
# _get_nvd_keyword() maps rule_ids to NVD search terms.
# Pure function - no mocking needed.
# ---------------------------------------------------------------------------

class TestGetNvdKeyword(unittest.TestCase):
    """
    _get_nvd_keyword() supports exact matches and prefix fallback.
    Rules with no mapping return None - the caller skips NVD lookup.
    """

    def test_exact_match_returns_specific_keyword(self):
        """A rule_id in the map returns its specific keyword."""
        result = _get_nvd_keyword("AZ-STOR-003")
        self.assertEqual(result, "Azure Storage lifecycle management")

    def test_prefix_fallback_when_specific_rule_absent(self):
        """
        A rule_id not in the map falls back to its prefix.
        AZ-STOR-099 has no entry, so it falls back to AZ-STOR.
        """
        result = _get_nvd_keyword("AZ-STOR-099")
        self.assertEqual(result, "Azure Storage Account")

    def test_returns_none_for_completely_unknown_rule(self):
        """A rule_id with no mapping at any prefix level returns None."""
        result = _get_nvd_keyword("AZ-UNKNOWN-999")
        self.assertIsNone(result)

    def test_kv_prefix_maps_correctly(self):
        """AZ-KV prefix maps to Azure Key Vault."""
        result = _get_nvd_keyword("AZ-KV-005")  # No specific entry for -005
        self.assertEqual(result, "Azure Key Vault")


# ---------------------------------------------------------------------------
# TestEnrichSingleFinding
# _enrich_single_finding() adds CVE fields to one finding dict.
# query_nvd is patched to avoid network calls.
# ---------------------------------------------------------------------------

class TestEnrichSingleFinding(unittest.TestCase):
    """
    _enrich_single_finding() takes a finding dict, looks up CVEs via
    query_nvd, and merges cve_references, cvss_score, and exploit_available
    into the dict. It never raises.
    """

    def setUp(self):
        _cache.clear()

    @patch("scanner.cve_correlator.query_nvd")
    def test_adds_cve_references_field(self, mock_query):
        """cve_references is added as a list of CVE dicts."""
        mock_query.return_value = [_MOCK_CVE]
        finding = {"rule_id": "AZ-STOR-003", "severity": "HIGH"}
        result = _enrich_single_finding(finding)
        self.assertIn("cve_references", result)
        self.assertEqual(len(result["cve_references"]), 1)
        self.assertEqual(result["cve_references"][0]["cve_id"], "CVE-2023-12345")

    @patch("scanner.cve_correlator.query_nvd")
    def test_cvss_score_is_highest_across_matches(self, mock_query):
        """
        cvss_score is the maximum score across all matched CVEs.
        Consumers should not need to iterate cve_references to find the worst case.
        """
        mock_query.return_value = [_MOCK_CVE, _MOCK_CVE_NO_EXPLOIT]
        finding = {"rule_id": "AZ-STOR-003", "severity": "HIGH"}
        result = _enrich_single_finding(finding)
        self.assertEqual(result["cvss_score"], 9.8)  # Max of 9.8 and 5.4

    @patch("scanner.cve_correlator.query_nvd")
    def test_exploit_available_true_when_any_cve_has_exploit(self, mock_query):
        """exploit_available is True if at least one CVE has a known exploit."""
        mock_query.return_value = [_MOCK_CVE_NO_EXPLOIT, _MOCK_CVE]
        finding = {"rule_id": "AZ-STOR-003", "severity": "HIGH"}
        result = _enrich_single_finding(finding)
        self.assertTrue(result["exploit_available"])

    @patch("scanner.cve_correlator.query_nvd")
    def test_exploit_available_false_when_no_cve_has_exploit(self, mock_query):
        """exploit_available is False when no matched CVE is in CISA KEV."""
        mock_query.return_value = [_MOCK_CVE_NO_EXPLOIT]
        finding = {"rule_id": "AZ-STOR-003", "severity": "HIGH"}
        result = _enrich_single_finding(finding)
        self.assertFalse(result["exploit_available"])

    @patch("scanner.cve_correlator.query_nvd")
    def test_unknown_rule_id_sets_empty_defaults(self, mock_query):
        """
        A rule_id with no keyword mapping returns empty CVE fields
        without calling query_nvd at all.
        """
        finding = {"rule_id": "AZ-UNKNOWN-999", "severity": "LOW"}
        result = _enrich_single_finding(finding)
        self.assertEqual(result["cve_references"], [])
        self.assertIsNone(result["cvss_score"])
        self.assertFalse(result["exploit_available"])
        mock_query.assert_not_called()

    @patch("scanner.cve_correlator.query_nvd")
    def test_does_not_overwrite_existing_finding_fields(self, mock_query):
        """
        CVE fields are additive - existing finding fields are not modified.
        """
        mock_query.return_value = [_MOCK_CVE]
        finding = {
            "rule_id": "AZ-STOR-003",
            "severity": "HIGH",
            "resource_id": "/subscriptions/xxx/...",
        }
        result = _enrich_single_finding(finding)
        self.assertEqual(result["severity"], "HIGH")
        self.assertEqual(result["resource_id"], "/subscriptions/xxx/...")


# ---------------------------------------------------------------------------
# TestEnrichFindings
# enrich_findings() is the public API - tests the list-level behaviour.
# ---------------------------------------------------------------------------

class TestEnrichFindings(unittest.TestCase):

    def setUp(self):
        _cache.clear()

    @patch("scanner.cve_correlator.query_nvd")
    def test_enriches_all_findings_in_list(self, mock_query):
        """All findings in the input list receive CVE fields."""
        mock_query.return_value = [_MOCK_CVE]
        findings = [
            {"rule_id": "AZ-STOR-003", "severity": "HIGH"},
            {"rule_id": "AZ-KV-002",   "severity": "CRITICAL"},
        ]
        results = enrich_findings(findings)
        self.assertEqual(len(results), 2)
        for r in results:
            self.assertIn("cve_references", r)
            self.assertIn("cvss_score", r)
            self.assertIn("exploit_available", r)

    @patch("scanner.cve_correlator.query_nvd")
    def test_returns_empty_list_unchanged(self, mock_query):
        """An empty input list returns [] without calling query_nvd."""
        results = enrich_findings([])
        self.assertEqual(results, [])
        mock_query.assert_not_called()

    @patch("scanner.cve_correlator.query_nvd")
    def test_preserves_input_order(self, mock_query):
        """Output order matches input order."""
        mock_query.return_value = []
        findings = [
            {"rule_id": "AZ-STOR-003", "id": 1},
            {"rule_id": "AZ-KV-002",   "id": 2},
            {"rule_id": "AZ-VM",        "id": 3},
        ]
        results = enrich_findings(findings)
        self.assertEqual([r["id"] for r in results], [1, 2, 3])


if __name__ == "__main__":
    unittest.main()
