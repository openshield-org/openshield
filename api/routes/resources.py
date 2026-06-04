"""Resources route: derive unique Azure resources from the latest scan's findings."""

import logging
import os
from flask import Blueprint, g, jsonify

from api.models.finding import DatabaseManager

resources_bp = Blueprint("resources", __name__)
logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


def _parse_resource_id(resource_id: str):
    """Extract subscription_id and resource_group from an ARM resource path."""
    parts = (resource_id or "").split("/")
    subscription_id = parts[2] if len(parts) > 2 else ""
    resource_group = parts[4] if len(parts) > 4 else ""
    return subscription_id, resource_group


@resources_bp.get("/api/resources")
def get_resources():
    """Return unique Azure resources derived from the most recent scan's findings.

    Groups findings by resource_id and surfaces the highest-severity finding per
    resource as the resource's risk level.
    """
    try:
        import psycopg2.extras

        db = _get_db()
        conn = db._get_conn()

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Get the most recent scan metadata
            cur.execute(
                "SELECT scan_id, started_at FROM scans WHERE total_findings > 0 ORDER BY started_at DESC LIMIT 1"
            )
            latest_scan = cur.fetchone()
            if not latest_scan:
                return jsonify({"summary": {"total": 0, "by_category": {}, "by_risk_level": {}, "last_scan_at": None}, "resources": []})

            cur.execute(
                """
                SELECT
                    resource_id,
                    resource_name,
                    resource_type,
                    category,
                    MIN(detected_at) AS discovered_at,
                    MAX(CASE severity
                        WHEN 'HIGH'   THEN 3
                        WHEN 'MEDIUM' THEN 2
                        WHEN 'LOW'    THEN 1
                        ELSE 0 END) AS risk_rank
                FROM findings
                WHERE scan_id = %s
                GROUP BY resource_id, resource_name, resource_type, category
                ORDER BY risk_rank DESC, resource_name
                """,
                (str(latest_scan["scan_id"]),),
            )
            rows = cur.fetchall()

        rank_to_risk = {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "NONE"}
        by_category: dict = {}
        by_risk_level: dict = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "NONE": 0}
        resources = []

        for row in rows:
            sub_id, rg = _parse_resource_id(row["resource_id"])
            risk = rank_to_risk.get(row["risk_rank"], "NONE")
            detected = row["discovered_at"]
            discovered_at = detected.isoformat() if hasattr(detected, "isoformat") else str(detected)

            resources.append({
                "id":              row["resource_id"],
                "name":            row["resource_name"],
                "type":            row["resource_type"],
                "category":        row["category"],
                "resource_group":  rg,
                "subscription_id": sub_id,
                "location":        "",
                "risk":            risk,
                "discovered_at":   discovered_at,
                "config":          {},
            })

            by_category[row["category"]] = by_category.get(row["category"], 0) + 1
            by_risk_level[risk] = by_risk_level.get(risk, 0) + 1

        last_scan_at = latest_scan["started_at"]
        if hasattr(last_scan_at, "isoformat"):
            last_scan_at = last_scan_at.isoformat()

        return jsonify({
            "summary": {
                "total":         len(resources),
                "by_category":   by_category,
                "by_risk_level": by_risk_level,
                "last_scan_at":  last_scan_at,
            },
            "resources": resources,
        })

    except Exception as exc:
        logger.error("Failed to build resources: %s", exc)
        return jsonify({"error": "Failed to retrieve resources", "detail": str(exc)}), 500
