"""Findings routes: list, retrieve, and get remediation playbooks for findings."""

import logging
import os
from pathlib import Path
from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager
from scanner.cve_correlator import enrich_findings

_PLAYBOOKS_DIR = Path(__file__).parent.parent.parent / "playbooks" / "cli"

findings_bp = Blueprint("findings", __name__)
logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


@findings_bp.get("/api/findings")
def list_findings():
    """Return findings, optionally filtered by severity, category, or rule_id.

    Query parameters:
        severity  - HIGH | MEDIUM | LOW | INFO
        category  - Storage | Network | Identity | Database | Compute | KeyVault
        rule_id   - e.g. AZ-STOR-001
        scan_id   - UUID of a specific scan
    """
    try:
        filters = {
            k: v
            for k, v in request.args.items()
            if k in ("severity", "category", "rule_id", "scan_id")
        }
        db = _get_db()
        findings = db.get_findings(filters)
        legacy_findings = [
            f
            for f in findings
            if f.get("cve_references") is None
            and f.get("cvss_score") is None
            and f.get("exploit_available") is None
        ]
        if legacy_findings:
            enrich_findings(legacy_findings)
            db.update_cve_fields(legacy_findings)
        return jsonify({"count": len(findings), "findings": findings})
    except Exception as exc:
        logger.error("Failed to list findings: %s", exc)
        return jsonify({"error": "Failed to retrieve findings", "detail": str(exc)}), 500


@findings_bp.get("/api/findings/<int:finding_id>")
def get_finding(finding_id: int):
    """Return a single finding by its integer ID."""
    try:
        db = _get_db()
        finding = db.get_finding_by_id(finding_id)
        if not finding:
            return jsonify({"error": "Finding not found"}), 404
        return jsonify(finding)
    except Exception as exc:
        logger.error("Failed to get finding %d: %s", finding_id, exc)
        return jsonify({"error": "Database error", "detail": str(exc)}), 500


@findings_bp.get("/api/findings/<int:finding_id>/playbook")
def get_playbook(finding_id: int):
    """Return a structured remediation playbook for a finding.

    Loads the pre-written Azure CLI script from playbooks/cli/ (keyed by rule_id)
    and combines it with the finding's remediation guidance and any CVE references.
    """
    try:
        db = _get_db()
        finding = db.get_finding_by_id(finding_id)
        if not finding:
            return jsonify({"error": "Finding not found"}), 404

        rule_id = finding.get("rule_id", "")
        remediation = finding.get("remediation", "")
        cve_refs = finding.get("cve_references") or []

        # Map rule_id (e.g. AZ-STOR-001) to script filename (fix_az_stor_001.sh)
        script_name = "fix_" + rule_id.lower().replace("-", "_") + ".sh"
        script_path = _PLAYBOOKS_DIR / script_name

        cli_commands = []
        if script_path.exists():
            raw = script_path.read_text()
            # Strip comment-only lines and blank lines; join multi-line commands
            lines = raw.splitlines()
            cmd_lines = [
                l for l in lines
                if l.strip() and not l.strip().startswith("#")
                and l.strip() not in ("set -e",)
            ]
            cli_commands = ["\n".join(cmd_lines)] if cmd_lines else []

        portal_steps = [remediation] if remediation else []

        validation_steps = [
            f"Open the Azure Portal and navigate to the resource.",
            f"Verify the security configuration matches the remediation guidance for {rule_id}.",
            "Re-run an OpenShield scan and confirm this finding no longer appears.",
        ]

        references = []
        for cve in cve_refs:
            cve_id = cve.get("cve_id", "")
            if cve_id:
                references.append(f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        if not references:
            references.append("https://learn.microsoft.com/en-us/azure/security/")

        return jsonify({
            "portal_steps":     portal_steps,
            "cli_commands":     cli_commands,
            "validation_steps": validation_steps,
            "references":       references,
        })

    except Exception as exc:
        logger.error("Failed to get playbook for finding %d: %s", finding_id, exc)
        return jsonify({"error": "Failed to retrieve playbook", "detail": str(exc)}), 500
