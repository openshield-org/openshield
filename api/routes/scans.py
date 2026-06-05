"""Scan routes: list historical scans and trigger new ones."""

import logging
import os
from flask import Blueprint, g, jsonify, request

from api.models.finding import DatabaseManager
from scanner.cve_correlator import enrich_findings

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


@scans_bp.post("/api/scans/<scan_id>/enrich")
def enrich_scan(scan_id):
    """Trigger CVE enrichment for an existing scan."""
    try:
        db = _get_db()
        
        # Check current status to avoid redundant NVD calls
        scans = db.get_scans()
        current_scan = next((s for s in scans if str(s["scan_id"]) == scan_id), None)
        
        if not current_scan:
            return jsonify({"error": "Scan not found"}), 404
            
        status = current_scan.get("cve_enrichment_status")
        if status == "COMPLETED":
            return jsonify({"message": "Scan already enriched", "scan_id": scan_id}), 200
        if status == "ENRICHING":
            return jsonify({"message": "Enrichment already in progress", "scan_id": scan_id}), 202

        findings = db.get_findings({"scan_id": scan_id})
        if not findings:
            return jsonify({"error": "No findings found for this scan"}), 404

        logger.info("Enriching %d findings for scan %s", len(findings), scan_id)
        db.update_scan_enrichment_status(scan_id, "ENRICHING")

        try:
            enriched = enrich_findings(findings)
            db.update_cve_fields(enriched)
            db.update_scan_enrichment_status(scan_id, "COMPLETED")
        except Exception as exc:
            logger.error("Enrichment failed for scan %s: %s", scan_id, exc)
            db.update_scan_enrichment_status(scan_id, "FAILED")
            return jsonify({"error": "Enrichment failed", "detail": str(exc)}), 500

        return jsonify({
            "scan_id": scan_id,
            "status": "COMPLETED",
            "enriched_count": len(enriched)
        })

    except Exception as exc:
        logger.error("Failed to enrich scan %s: %s", scan_id, exc)
        return jsonify({"error": "Internal server error", "detail": str(exc)}), 500