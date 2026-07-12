"""Tests for GET /api/findings/<id>/playbook (SEC-005 path traversal guard)."""

from unittest.mock import MagicMock, patch

import api.routes.findings as findings_route


def _finding(rule_id, remediation="Do the thing.", cve_references=None):
    return {
        "rule_id": rule_id,
        "remediation": remediation,
        "cve_references": cve_references or [],
    }


def _mock_db(finding):
    db = MagicMock()
    db.get_finding_by_id.return_value = finding
    return db


def _get_playbook(client, auth_headers, finding):
    with patch.object(findings_route, "_get_db", return_value=_mock_db(finding)):
        return client.get("/api/findings/1/playbook", headers=auth_headers)


def test_valid_rule_id_returns_playbook(client, auth_headers):
    resp = _get_playbook(client, auth_headers, _finding("AZ-STOR-001"))
    assert resp.status_code == 200
    assert resp.get_json()["cli_commands"]


def test_missing_finding_returns_404(client, auth_headers):
    with patch.object(findings_route, "_get_db", return_value=_mock_db(None)):
        resp = client.get("/api/findings/999/playbook", headers=auth_headers)
    assert resp.status_code == 404


def test_dotdot_rule_id_does_not_escape_playbooks_dir(client, auth_headers):
    resp = _get_playbook(client, auth_headers, _finding("../../../../etc/passwd"))
    assert resp.status_code == 200
    assert resp.get_json()["cli_commands"] == []


def test_rule_id_with_path_separator_rejected(client, auth_headers):
    resp = _get_playbook(client, auth_headers, _finding("AZ/STOR/001"))
    assert resp.status_code == 200
    assert resp.get_json()["cli_commands"] == []


def test_absolute_path_rule_id_rejected(client, auth_headers):
    resp = _get_playbook(client, auth_headers, _finding("/etc/passwd"))
    assert resp.status_code == 200
    assert resp.get_json()["cli_commands"] == []


def test_unknown_but_well_formed_rule_id_returns_empty_commands(client, auth_headers):
    resp = _get_playbook(client, auth_headers, _finding("AZ-NOPE-999"))
    assert resp.status_code == 200
    assert resp.get_json()["cli_commands"] == []
