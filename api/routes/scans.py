"""Scan routes: list historical scans and trigger new ones."""

import logging
import os
from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager

scans_bp = Blueprint("scans", __name__)
logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    if "db" not in g:
        db_url = os.environ.get("DATABASE_URL")
        if not db_url:
            raise RuntimeError("DATABASE_URL environment variable is not set")
        g.db = DatabaseManager(db_url)
        g.db.connect()
    return g.db


@scans_bp.get("/api/scans")
def list_scans():
    """Return all historical scan results ordered by most recent first."""
    try:
        db = _get_db()
        result = db.get_scans()
        return jsonify(result)
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
    try:
        from scanner.engine import ScanEngine
    except ImportError:
        return jsonify({"error": "Scanner module is not available"}), 500

    try:
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
            logger.error("Scan engine execution failed: %s", exc, exc_info=True)
            return jsonify({"error": "Scan failed", "detail": str(exc)}), 500

        if not isinstance(result, dict) or "scan_id" not in result:
            return jsonify({"error": "Invalid scan result returned"}), 500

        try:
            db = _get_db()
            db.save_scan(result)
        except Exception as exc:
            logger.error("Failed to save scan result: %s", exc, exc_info=True)
            return jsonify({"error": "Database save failed", "detail": str(exc)}), 500

        return jsonify(result), 201

    except Exception as exc:
        logger.error("Critical error in trigger_scan route: %s", exc, exc_info=True)
        return jsonify({"error": "Critical route failure", "detail": str(exc)}), 500