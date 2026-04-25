"""Findings routes: list and retrieve individual findings."""

import os
from flask import Blueprint, jsonify, request

from api.models.finding import DatabaseManager

findings_bp = Blueprint("findings", __name__)


def _get_db() -> DatabaseManager:
    db = DatabaseManager(os.environ["DATABASE_URL"])
    db.connect()
    return db


@findings_bp.get("/api/findings")
def list_findings():
    """Return findings, optionally filtered by severity, category, or rule_id.

    Query parameters:
        severity  — HIGH | MEDIUM | LOW | INFO
        category  — Storage | Network | Identity | Database | Compute | KeyVault
        rule_id   — e.g. AZ-STOR-001
        scan_id   — UUID of a specific scan
    """
    filters = {
        k: v
        for k, v in request.args.items()
        if k in ("severity", "category", "rule_id", "scan_id")
    }
    db = _get_db()
    findings = db.get_findings(filters)
    return jsonify({"count": len(findings), "findings": findings})


@findings_bp.get("/api/findings/<int:finding_id>")
def get_finding(finding_id: int):
    """Return a single finding by its integer ID."""
    db = _get_db()
    finding = db.get_finding_by_id(finding_id)
    if not finding:
        return jsonify({"error": "Finding not found"}), 404
    return jsonify(finding)
