"""Drift route: compare the two most recent scans to surface configuration changes."""

import logging
import os
from flask import Blueprint, g, jsonify

from api.models.finding import DatabaseManager

drift_bp = Blueprint("drift", __name__)
logger = logging.getLogger(__name__)


def _get_db() -> DatabaseManager:
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


def _ts(value) -> str:
    """Normalise a datetime or string to an ISO-8601 string."""
    return value.isoformat() if hasattr(value, "isoformat") else str(value)


@drift_bp.get("/api/drift")
def get_drift():
    """Return configuration drift derived by comparing the two most recent scans.

    ADDED   = (rule_id, resource_id) in the latest scan but not the previous one.
    REMOVED = (rule_id, resource_id) in the previous scan but not the latest one.

    If only one scan exists the response returns an empty event list.
    """
    try:
        import psycopg2.extras

        db = _get_db()
        conn = db._get_conn()

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT scan_id, started_at FROM scans WHERE total_findings > 0 ORDER BY started_at DESC LIMIT 2"
            )
            scans = cur.fetchall()

        if len(scans) < 2:
            last_checked = _ts(scans[0]["started_at"]) if scans else None
            return jsonify({
                "summary": {"total": 0, "added": 0, "removed": 0, "modified": 0, "last_checked": last_checked},
                "events": [],
            })

        latest_id   = str(scans[0]["scan_id"])
        previous_id = str(scans[1]["scan_id"])
        last_checked = _ts(scans[0]["started_at"])
        prev_ts      = _ts(scans[1]["started_at"])

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT rule_id, resource_id, resource_name, resource_type,
                       category, severity, scan_id
                FROM findings
                WHERE scan_id IN (%s, %s)
                """,
                (latest_id, previous_id),
            )
            rows = cur.fetchall()

        # Build lookup: key = (rule_id, resource_id) → row, per scan
        latest_map: dict   = {}
        previous_map: dict = {}
        for row in rows:
            key = (row["rule_id"], row["resource_id"])
            if str(row["scan_id"]) == latest_id:
                latest_map[key] = row
            else:
                previous_map[key] = row

        added_keys   = set(latest_map) - set(previous_map)
        removed_keys = set(previous_map) - set(latest_map)

        def _rg(resource_id: str) -> str:
            parts = (resource_id or "").split("/")
            return parts[4] if len(parts) > 4 else ""

        events = []
        event_id = 1

        for key in sorted(added_keys, key=lambda k: k[0]):
            row = latest_map[key]
            events.append({
                "id":             event_id,
                "type":           "ADDED",
                "severity":       row["severity"],
                "resource_name":  row["resource_name"],
                "resource_type":  row["resource_type"],
                "resource_group": _rg(row["resource_id"]),
                "field":          "security_policy",
                "old_value":      None,
                "new_value":      row["severity"],
                "changed_by":     "azure-policy-scan",
                "changed_at":     last_checked,
                "rule_violated":  row["rule_id"],
            })
            event_id += 1

        for key in sorted(removed_keys, key=lambda k: k[0]):
            row = previous_map[key]
            events.append({
                "id":             event_id,
                "type":           "REMOVED",
                "severity":       row["severity"],
                "resource_name":  row["resource_name"],
                "resource_type":  row["resource_type"],
                "resource_group": _rg(row["resource_id"]),
                "field":          "security_policy",
                "old_value":      row["severity"],
                "new_value":      None,
                "changed_by":     "azure-policy-scan",
                "changed_at":     prev_ts,
                "rule_violated":  row["rule_id"],
            })
            event_id += 1

        # Sort all events by changed_at desc
        events.sort(key=lambda e: e["changed_at"] or "", reverse=True)

        return jsonify({
            "summary": {
                "total":        len(events),
                "added":        len(added_keys),
                "removed":      len(removed_keys),
                "modified":     0,
                "last_checked": last_checked,
            },
            "events": events,
        })

    except Exception as exc:
        logger.error("Failed to compute drift: %s", exc)
        return jsonify({"error": "Failed to retrieve drift", "detail": str(exc)}), 500
