"""Scan routes: list historical scans and trigger new ones."""

import logging
import os
from flask import Blueprint, jsonify, request

from api.models.finding import DatabaseManager

scans_bp = Blueprint("scans", __name__)
logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    db = DatabaseManager(os.environ["DATABASE_URL"])
    db.connect()
    return db


@scans_bp.get("/api/scans")
def list_scans():
    """Return all historical scan results ordered by most recent first."""
    try:
        db = _get_db()
        scans = db.get_scans()
        return jsonify({"count": len(scans), "scans": scans})
    except Exception as exc:
        logger.error("Failed to list scans: %s", exc)
        return jsonify({"error": "Failed to retrieve scans", "detail": str(exc)}), 500


@scans_bp.post("/api/scans/trigger")
def trigger_scan():
    """Trigger a synchronous scan against the configured subscription.

    Accepts an optional JSON body with ``subscription_id``. Falls back to the
    ``AZURE_SUBSCRIPTION_ID`` environment variable if not provided.

    Note: For production use, replace this with an async task queue (e.g.
    Celery or Azure Functions) to avoid request timeouts on large subscriptions.
    """
    from scanner.engine import ScanEngine  # deferred to avoid import at startup

    body = request.get_json(silent=True) or {}
    subscription_id = body.get("subscription_id") or os.environ.get(
        "AZURE_SUBSCRIPTION_ID"
    )

    if not subscription_id:
        return jsonify({"error": "subscription_id is required"}), 400

    logger.info("Scan triggered for subscription %s", subscription_id)

    try:
        engine = ScanEngine(subscription_id)
        result = engine.run_scan()
    except Exception as exc:
        logger.error("Scan engine execution failed: %s", exc)
        return jsonify({"error": "Scan failed", "detail": str(exc)}), 500

    try:
        db = _get_db()
        # Note: Table creation is handled at startup; no need to repeat it here.
        db.save_scan(result)
    except Exception as exc:
        logger.error("Failed to save scan result to database: %s", exc)
        return jsonify({"error": "Database save failed", "detail": str(exc)}), 500

    return jsonify(result), 201
