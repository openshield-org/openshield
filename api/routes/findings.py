"""Findings routes: list and retrieve individual findings."""

import logging
import os
from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager

findings_bp = Blueprint("findings", __name__)
logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    if "db_conn" not in g:
        g.db_conn = DatabaseManager(os.environ["DATABASE_URL"])
        g.db_conn.connect()
    return g.db_conn


@findings_bp.get("/api/findings")
def list_findings():
    """Return findings, optionally filtered by severity, category, or rule_id.

    Query parameters:
        severity  — HIGH | MEDIUM | LOW | INFO
        category  — Storage | Network | Identity | Database | Compute | KeyVault
        rule_id   — e.g. AZ-STOR-001
        scan_id   — UUID of a specific scan
    """
    try:
        filters = {
            k: v
            for k, v in request.args.items()
            if k in ("severity", "category", "rule_id", "scan_id")
        }
        db = _get_db()
        findings = db.get_findings(filters)
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
