"""Prioritization route: rank findings by severity, affected resources, and remediation effort."""

import logging
import os
from flask import Blueprint, g, jsonify

from api.models.finding import DatabaseManager, SEVERITY_WEIGHTS

prioritization_bp = Blueprint("prioritization", __name__)
logger = logging.getLogger(__name__)

# Estimated remediation effort (1 = fastest, 4 = slowest) per category
_EFFORT = {
    "Storage":    1,
    "Network":    2,
    "Database":   2,
    "Compute":    2,
    "Identity":   3,
    "KeyVault":   2,
    "Monitoring": 1,
}
_DEFAULT_EFFORT = 2

_EFFORT_ETA = {1: "15 mins", 2: "1 hour", 3: "1 day", 4: "1 week"}
_EFFORT_LABEL = {1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "HIGH"}

# 1-10 risk score per severity for the matrix
_RISK_SCORE = {"HIGH": 8, "MEDIUM": 5, "LOW": 2, "INFO": 1}

# Composite score threshold → impact label
def _impact(score: int) -> str:
    if score >= 40:
        return "CRITICAL"
    if score >= 20:
        return "HIGH"
    if score >= 10:
        return "MEDIUM"
    return "LOW"


def _get_db() -> DatabaseManager:
    if "db" not in g:
        g.db = DatabaseManager(os.environ["DATABASE_URL"])
        g.db.connect()
    return g.db


@prioritization_bp.get("/api/prioritization")
def get_prioritization():
    """Return a risk-ranked prioritization view derived from the latest scan's findings.

    Aggregates findings by rule, scores each rule by (severity_weight × affected_resource_count),
    and sorts descending to surface the highest-priority fixes first.
    """
    try:
        import psycopg2.extras

        db = _get_db()
        conn = db._get_conn()

        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT scan_id FROM scans WHERE total_findings > 0 ORDER BY started_at DESC LIMIT 1"
            )
            row = cur.fetchone()
            if not row:
                empty = {"matrix": [], "rankings": [], "action_items": [], "summary": {}}
                return jsonify(empty)
            latest_scan_id = str(row["scan_id"])

            cur.execute(
                """
                SELECT
                    rule_id,
                    rule_name,
                    severity,
                    category,
                    remediation,
                    COUNT(DISTINCT resource_id) AS affected_count,
                    MIN(resource_name)          AS resource_name
                FROM findings
                WHERE scan_id = %s
                GROUP BY rule_id, rule_name, severity, category, remediation
                ORDER BY affected_count DESC
                """,
                (latest_scan_id,),
            )
            rules = cur.fetchall()

            cur.execute("SELECT COUNT(*) AS total FROM findings WHERE scan_id = %s", (latest_scan_id,))
            total_findings = cur.fetchone()["total"]

        matrix = []
        rankings = []
        action_items = []
        severity_counts: dict = {}

        for idx, rule in enumerate(rules):
            sev = (rule["severity"] or "LOW").upper()
            cat = rule["category"] or "Other"
            effort = _EFFORT.get(cat, _DEFAULT_EFFORT)
            weight = SEVERITY_WEIGHTS.get(sev, 2)
            affected = rule["affected_count"]
            score = weight * affected
            risk = _RISK_SCORE.get(sev, 2)

            severity_counts[sev] = severity_counts.get(sev, 0) + affected

            matrix.append({
                "id":                idx + 1,
                "rule_id":           rule["rule_id"],
                "name":              rule["rule_name"],
                "risk":              risk,
                "effort":            effort,
                "category":          cat,
                "severity":          sev,
                "affected_resources": affected,
                "resource":          rule["resource_name"],
            })

            rankings.append({
                "rank":     idx + 1,   # re-sorted below
                "rule_id":  rule["rule_id"],
                "name":     rule["rule_name"],
                "score":    score,
                "severity": sev,
                "category": cat,
                "effort":   effort,
                "impact":   _impact(score),
                "resource": rule["resource_name"],
            })

            # Top 10 rules → action items
            if len(action_items) < 10:
                action_items.append({
                    "id":      idx + 1,
                    "action":  rule["remediation"] or f"Remediate {rule['rule_name']}",
                    "impact":  _impact(score),
                    "effort":  _EFFORT_LABEL.get(effort, "MEDIUM"),
                    "eta":     _EFFORT_ETA.get(effort, "1 hour"),
                    "rule_id": rule["rule_id"],
                    "resource": rule["resource_name"],
                })

        # Sort rankings by score desc and re-assign ranks
        rankings.sort(key=lambda r: r["score"], reverse=True)
        for i, r in enumerate(rankings):
            r["rank"] = i + 1

        critical = severity_counts.get("HIGH", 0)
        total_hours = sum(
            _EFFORT.get(r["category"], _DEFAULT_EFFORT)
            for r in matrix
            if r["severity"] in ("HIGH", "MEDIUM")
        )
        estimated_time = f"{total_hours} hours" if total_hours < 24 else f"{total_hours // 8} days"

        summary = {
            "totalFindings":           total_findings,
            "criticalFindings":        critical,
            "highRiskFindings":        severity_counts.get("HIGH", 0),
            "mediumRiskFindings":      severity_counts.get("MEDIUM", 0),
            "lowRiskFindings":         severity_counts.get("LOW", 0),
            "recommendedActionsCount": len(action_items),
            "estimatedFixTime":        estimated_time,
            "topPriority":             rankings[0]["name"] if rankings else "No findings",
        }

        return jsonify({
            "matrix":       matrix,
            "rankings":     rankings[:25],
            "action_items": action_items,
            "summary":      summary,
        })

    except Exception as exc:
        logger.error("Failed to build prioritization: %s", exc)
        return jsonify({"error": "Failed to retrieve prioritization", "detail": str(exc)}), 500
