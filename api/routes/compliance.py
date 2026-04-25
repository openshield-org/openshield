"""Compliance routes: framework-specific posture breakdown."""

import os
from flask import Blueprint, jsonify

from api.models.finding import DatabaseManager

compliance_bp = Blueprint("compliance", __name__)

SUPPORTED_FRAMEWORKS = ("cis", "nist", "iso27001")


def _get_db() -> DatabaseManager:
    db = DatabaseManager(os.environ["DATABASE_URL"])
    db.connect()
    return db


@compliance_bp.get("/api/compliance/<framework>")
def get_compliance(framework: str):
    """Return pass/fail compliance breakdown for a framework.

    Supported frameworks: cis, nist, iso27001

    Returns control-level pass/fail status mapped to current open findings.
    """
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
