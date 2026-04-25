"""Scan engine: loads rules dynamically and orchestrates a full subscription scan."""

import importlib.util
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from scanner.azure_client import AzureClient

logger = logging.getLogger(__name__)

RULES_DIR = Path(__file__).parent / "rules"


class ScanEngine:
    """Orchestrates Azure CSPM scans against a target subscription.

    Rules are loaded dynamically at initialisation time from ``scanner/rules/``.
    Each rule module must expose a ``scan(azure_client, subscription_id)``
    function and the module-level constants ``RULE_ID``, ``RULE_NAME``,
    ``SEVERITY``, ``CATEGORY``, ``FRAMEWORKS``, ``DESCRIPTION``,
    ``REMEDIATION``, and ``PLAYBOOK``.
    """

    def __init__(self, subscription_id: str) -> None:
        self.subscription_id = subscription_id
        self.client = AzureClient(subscription_id)
        self.rules: List[Any] = []
        self.load_rules()

    # ------------------------------------------------------------------ #
    # Rule loading                                                          #
    # ------------------------------------------------------------------ #

    def load_rules(self) -> None:
        """Dynamically import every *.py file in scanner/rules/ as a rule module."""
        for rule_path in sorted(RULES_DIR.glob("*.py")):
            if rule_path.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    rule_path.stem, rule_path
                )
                module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
                spec.loader.exec_module(module)  # type: ignore[union-attr]
                if callable(getattr(module, "scan", None)):
                    self.rules.append(module)
                    logger.info(
                        "Loaded rule: %s", getattr(module, "RULE_ID", rule_path.stem)
                    )
                else:
                    logger.warning(
                        "Rule file %s has no scan() function — skipped", rule_path.name
                    )
            except Exception as exc:
                logger.error("Failed to load rule %s: %s", rule_path.name, exc)

    # ------------------------------------------------------------------ #
    # Scan execution                                                        #
    # ------------------------------------------------------------------ #

    def run_scan(self) -> Dict[str, Any]:
        """Execute all loaded rules and return a normalised scan result.

        Returns:
            dict with keys: scan_id, subscription_id, started_at,
            completed_at, total_findings, findings.
        """
        scan_id = str(uuid.uuid4())
        started_at = datetime.now(timezone.utc).isoformat()
        findings: List[Dict[str, Any]] = []
        detected_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Scan %s starting against subscription %s — %d rules loaded",
            scan_id,
            self.subscription_id,
            len(self.rules),
        )

        for rule in self.rules:
            rule_id = getattr(rule, "RULE_ID", "UNKNOWN")
            try:
                rule_findings = rule.scan(self.client, self.subscription_id)
                for finding in rule_findings:
                    finding.setdefault("detected_at", detected_at)
                    finding.setdefault("scan_id", scan_id)
                findings.extend(rule_findings)
                logger.info(
                    "Rule %s produced %d finding(s)", rule_id, len(rule_findings)
                )
            except Exception as exc:
                logger.error("Rule %s raised an exception: %s", rule_id, exc)

        completed_at = datetime.now(timezone.utc).isoformat()

        logger.info(
            "Scan %s complete — %d total finding(s)", scan_id, len(findings)
        )

        return {
            "scan_id": scan_id,
            "subscription_id": self.subscription_id,
            "started_at": started_at,
            "completed_at": completed_at,
            "total_findings": len(findings),
            "findings": findings,
        }
