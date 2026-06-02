"""Compliance routes: framework-specific posture breakdown."""

import logging
import os
from flask import Blueprint, g, jsonify

from api.models.finding import DatabaseManager

compliance_bp = Blueprint("compliance", __name__)
logger = logging.getLogger(__name__)

SUPPORTED_FRAMEWORKS = ("cis", "nist", "iso27001", "soc2")


def _get_db() -> DatabaseManager:
    if "db" not in g:
        db_url = os.environ.get("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL environment variable is not set")
        g.db = DatabaseManager(db_url)
        g.db.connect()
    return g.db


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
    except FileNotFoundError as exc:
        return jsonify({"error": f"Frameworks directory not found: {exc}"}), 500
    except Exception as exc:
        logger.error("Failed to retrieve compliance score for %s: %s", framework, exc)
        return jsonify({"error": "Compliance calculation failed", "detail": str(exc)}), 500