"""Scan routes: list historical scans and trigger new ones."""

import logging
import os
import uuid
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


@scans_bp.get("/api/scans/<scan_id>")
def get_scan_status(scan_id):
    """Return the details and status of a specific scan."""
    try:
        db = _get_db()
        scan = db.get_scan(scan_id)
        if not scan:
            return jsonify({"error": "Scan not found"}), 404
        return jsonify(scan)
    except Exception as exc:
        logger.error("Failed to get scan status: %s", exc)
        return jsonify({"error": "Database error", "detail": str(exc)}), 500


@scans_bp.post("/api/scans/trigger")
def trigger_scan():
    """Trigger an asynchronous scan against the configured subscription.

    Accepts an optional JSON body with ``subscription_id``. Falls back to the
    ``AZURE_SUBSCRIPTION_ID`` environment variable if not provided.

    Returns 202 Accepted with the scan_id immediately.
    """
    try:
        body = request.get_json(silent=True) or {}
        subscription_id = body.get("subscription_id") or os.environ.get(
            "AZURE_SUBSCRIPTION_ID"
        )

        if not subscription_id:
            return jsonify({"error": "subscription_id is required"}), 400

        scan_id = str(uuid.uuid4())
        logger.info("Async scan triggered for subscription %s (id: %s)", subscription_id, scan_id)

        try:
            db = _get_db()
            db.create_pending_scan(scan_id, subscription_id)
        except Exception as exc:
            logger.error("Failed to create pending scan: %s", exc, exc_info=True)
            return jsonify({"error": "Database error", "detail": str(exc)}), 500

        return jsonify({
            "scan_id": scan_id,
            "status": "pending",
            "message": "Scan has been queued and will start shortly."
        }), 202

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