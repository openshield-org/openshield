"""Finding dataclass and PostgreSQL-backed DatabaseManager."""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import psycopg2
import psycopg2.extras

logger = logging.getLogger(__name__)

FRAMEWORKS_DIR = Path(__file__).parent.parent.parent / "compliance" / "frameworks"

SEVERITY_WEIGHTS = {"HIGH": 10, "MEDIUM": 5, "LOW": 2, "INFO": 0}

FRAMEWORK_FILE_MAP = {
    "cis": "cis_azure_benchmark.json",
    "nist": "nist_csf.json",
    "iso27001": "iso27001.json",
    "soc2": "soc2.json",
}


@dataclass
class Finding:
    """Represents a single security misconfiguration finding."""

    rule_id: str
    rule_name: str
    severity: str
    category: str
    resource_id: str
    resource_name: str
    resource_type: str
    description: str
    remediation: str
    frameworks: Dict[str, str]
    detected_at: str
    scan_id: Optional[str] = None
    playbook: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    id: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "category": self.category,
            "resource_id": self.resource_id,
            "resource_name": self.resource_name,
            "resource_type": self.resource_type,
            "description": self.description,
            "remediation": self.remediation,
            "frameworks": self.frameworks,
            "detected_at": self.detected_at,
            "scan_id": self.scan_id,
            "playbook": self.playbook,
            "metadata": self.metadata,
        }


class DatabaseManager:
    """Manages PostgreSQL persistence for scans, findings, and scoring.

    All public methods open a new connection on first use. Call connect()
    explicitly if you want to pre-warm the connection.
    """

    def __init__(self, dsn: Optional[str] = None) -> None:
        self.dsn = dsn or os.environ["DATABASE_URL"]
        self.conn: Optional[Any] = None

    # ------------------------------------------------------------------ #
    # Connection                                                            #
    # ------------------------------------------------------------------ #

    def connect(self) -> None:
        """Open a persistent database connection and set the search path."""
        self.conn = psycopg2.connect(self.dsn)
        self.conn.autocommit = True  # Set to True for schema management
        with self.conn.cursor() as cur:
            # Ensure the openshield schema exists and is preferred in the search path.
            # This avoids 'permission denied for schema public' in restricted environments.
            cur.execute("CREATE SCHEMA IF NOT EXISTS openshield;")
            cur.execute("SET search_path TO openshield, public;")
        self.conn.autocommit = False
        logger.info("Database connection established (schema: openshield)")

    def _get_conn(self) -> Any:
        if self.conn is None or self.conn.closed:
            self.connect()
        return self.conn

    # ------------------------------------------------------------------ #
    # Schema                                                                #
    # ------------------------------------------------------------------ #

    def init_db(self) -> None:
        """Alias for create_tables to match startup script expectations."""
        self.create_tables()

    def create_tables(self) -> None:
        """Create the findings, scans, and rules tables if they do not exist."""
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id         UUID PRIMARY KEY,
                    subscription_id TEXT NOT NULL,
                    started_at      TIMESTAMPTZ NOT NULL,
                    completed_at    TIMESTAMPTZ,
                    total_findings  INTEGER DEFAULT 0
                );
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id              SERIAL PRIMARY KEY,
                    scan_id         UUID REFERENCES scans(scan_id),
                    rule_id         TEXT NOT NULL,
                    rule_name       TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    category        TEXT,
                    resource_id     TEXT,
                    resource_name   TEXT,
                    resource_type   TEXT,
                    description     TEXT,
                    remediation     TEXT,
                    playbook        TEXT,
                    frameworks      JSONB,
                    metadata        JSONB,
                    detected_at     TIMESTAMPTZ NOT NULL
                );
            """)
            cur.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_scan_id
                    ON findings(scan_id);
                CREATE INDEX IF NOT EXISTS idx_findings_severity
                    ON findings(severity);
                CREATE INDEX IF NOT EXISTS idx_findings_rule_id
                    ON findings(rule_id);
            """)
        conn.commit()
        logger.info("Database tables created / verified")

    # ------------------------------------------------------------------ #
    # Write                                                                 #
    # ------------------------------------------------------------------ #

    def save_scan(self, scan_result: Dict[str, Any]) -> None:
        """Persist a full scan result (scan header + all findings)."""
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO scans (scan_id, subscription_id, started_at, completed_at, total_findings)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (scan_id) DO NOTHING
                """,
                (
                    scan_result["scan_id"],
                    scan_result["subscription_id"],
                    scan_result["started_at"],
                    scan_result["completed_at"],
                    scan_result["total_findings"],
                ),
            )
            for f in scan_result.get("findings", []):
                cur.execute(
                    """
                    INSERT INTO findings
                        (scan_id, rule_id, rule_name, severity, category,
                         resource_id, resource_name, resource_type,
                         description, remediation, playbook,
                         frameworks, metadata, detected_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    """,
                    (
                        f.get("scan_id"),
                        f.get("rule_id"),
                        f.get("rule_name"),
                        f.get("severity"),
                        f.get("category"),
                        f.get("resource_id"),
                        f.get("resource_name"),
                        f.get("resource_type"),
                        f.get("description"),
                        f.get("remediation"),
                        f.get("playbook"),
                        json.dumps(f.get("frameworks", {})),
                        json.dumps(f.get("metadata", {})),
                        f.get("detected_at"),
                    ),
                )
        conn.commit()
        logger.info("Saved scan %s with %d findings", scan_result["scan_id"], scan_result["total_findings"])

    # ------------------------------------------------------------------ #
    # Read                                                                  #
    # ------------------------------------------------------------------ #

    def get_findings(self, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Return findings, optionally filtered by severity, category, or rule_id."""
        filters = filters or {}
        clauses: List[str] = []
        params: List[Any] = []

        if "severity" in filters:
            clauses.append("severity = %s")
            params.append(filters["severity"].upper())
        if "category" in filters:
            clauses.append("LOWER(category) = LOWER(%s)")
            params.append(filters["category"])
        if "rule_id" in filters:
            clauses.append("rule_id = %s")
            params.append(filters["rule_id"])
        if "scan_id" in filters:
            clauses.append("scan_id = %s")
            params.append(filters["scan_id"])

        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        sql = f"SELECT * FROM findings {where} ORDER BY detected_at DESC LIMIT 1000"

        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(row) for row in cur.fetchall()]

    def get_finding_by_id(self, finding_id: int) -> Optional[Dict[str, Any]]:
        """Return a single finding by its integer primary key."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM findings WHERE id = %s", (finding_id,))
            row = cur.fetchone()
            return dict(row) if row else None

    def get_scans(self) -> List[Dict[str, Any]]:
        """Return all scan records ordered by most recent first."""
        conn = self._get_conn()
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM scans ORDER BY started_at DESC LIMIT 100")
            return [dict(row) for row in cur.fetchall()]

    # ------------------------------------------------------------------ #
    # Scoring                                                               #
    # ------------------------------------------------------------------ #

    def get_score(self) -> int:
        """Return a 0–100 security posture score based on open findings.

        HIGH findings deduct 10 points each, MEDIUM 5, LOW 2.
        Score floors at 0.
        """
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
            )
            rows = cur.fetchall()

        deduction = sum(
            SEVERITY_WEIGHTS.get(sev.upper(), 0) * count for sev, count in rows
        )
        return max(0, 100 - deduction)

    def get_compliance_score(self, framework: str) -> Dict[str, Any]:
        """Return pass/fail breakdown against a compliance framework.

        Args:
            framework: One of 'cis', 'nist', or 'iso27001'.

        Returns:
            dict with keys: framework, total_controls, passed, failed,
            score_percent, controls (list of control detail objects).
        """
        filename = FRAMEWORK_FILE_MAP.get(framework.lower())
        if not filename:
            return {"error": f"Unknown framework: {framework}"}

        framework_path = FRAMEWORKS_DIR / filename
        if not framework_path.exists():
            return {"error": f"Framework file not found: {filename}"}

        with open(framework_path) as fh:
            framework_data = json.load(fh)

        controls = framework_data.get("controls", {})

        # Get rule IDs that have at least one finding
        conn = self._get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT DISTINCT rule_id FROM findings")
            failed_rule_ids = {row[0] for row in cur.fetchall()}

        results = []
        for rule_id, control in controls.items():
            status = "FAIL" if rule_id in failed_rule_ids else "PASS"
            results.append({
                "rule_id": rule_id,
                "control_id": control["control_id"],
                "control_name": control["control_name"],
                "status": status,
            })

        total = len(results)
        passed = sum(1 for r in results if r["status"] == "PASS")
        failed = total - passed
        score_pct = round((passed / total) * 100) if total else 0

        return {
            "framework": framework_data.get("framework"),
            "version": framework_data.get("version"),
            "total_controls": total,
            "passed": passed,
            "failed": failed,
            "score_percent": score_pct,
            "controls": results,
        }
