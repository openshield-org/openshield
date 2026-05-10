"""Compliance routes: framework-specific posture breakdown."""

import logging
import os
from flask import Blueprint, g, jsonify

from api.models.finding import DatabaseManager

compliance_bp = Blueprint("compliance", __name__)
logger = logging.getLogger(__name__)

SUPPORTED_FRAMEWORKS = ("cis", "nist", "iso27001", "soc2")


def _get_db() -> DatabaseManager:
    if "db_conn" not in g:
        g.db_conn = DatabaseManager(os.environ["DATABASE_URL"])
        g.db_conn.connect()
    return g.db_conn


@compliance_bp.get("/api/compliance/<framework>")
def get_compliance(framework: str):
    """Return pass/fail compliance breakdown for a framework.

    Supported frameworks: cis, nist, iso27001, soc2

    Returns control-level pass/fail status mapped to current open findings.
    """
    try:
        if framework.lower() not in SUPPORTED_FRAMEWORKS:
            return jsonify({
                "error": f"Unknown framework '{framework}'",
                "supported": list(SUPPORTED_FRAMEWORKS),
            }), 400

        db = _get_db()
        result = db.get_compliance_score(framework.lower())

        if "error" in result:
            return jsonify(result), 500

        return jsonify(result)
    except Exception as exc:
        logger.error("Failed to retrieve compliance score for %s: %s", framework, exc)
        return jsonify({"error": "Compliance calculation failed", "detail": str(exc)}), 500
