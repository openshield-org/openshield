"""
Document loader for OpenShield rules and compliance frameworks.
Loads scanner rules, CIS, NIST, ISO 27001 and SOC2 controls
into structured documents ready for chunking and embedding.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List

logger = logging.getLogger(__name__)

# Root of the OpenShield project
PROJECT_ROOT = Path(__file__).parent.parent

RULES_DIR = PROJECT_ROOT / "scanner" / "rules"
COMPLIANCE_DIR = PROJECT_ROOT / "compliance" / "frameworks"

COMPLIANCE_FILES = {
    "CIS Azure Benchmark": COMPLIANCE_DIR / "cis_azure_benchmark.json",
    "NIST CSF": COMPLIANCE_DIR / "nist_csf.json",
    "ISO 27001": COMPLIANCE_DIR / "iso27001.json",
    "SOC2": COMPLIANCE_DIR / "soc2.json",
}


def load_rule_documents() -> List[Dict[str, Any]]:
    """
    Load all OpenShield scanner rules as documents.

    Each rule file is parsed for its constants and returned
    as a structured document with metadata.

    Returns:
        List of document dicts with content and metadata.
    """
    documents = []

    for rule_file in sorted(RULES_DIR.glob("az_*.py")):
        try:
            content = rule_file.read_text(encoding="utf-8")

            # Extract key fields using simple string parsing
            rule_id = _extract_string(content, "RULE_ID")
            rule_name = _extract_string(content, "RULE_NAME")
            severity = _extract_string(content, "SEVERITY")
            category = _extract_string(content, "CATEGORY")
            description = _extract_multiline(content, "DESCRIPTION")
            remediation = _extract_multiline(content, "REMEDIATION")

            if not rule_id:
                logger.warning("Skipping %s — no RULE_ID found", rule_file.name)
                continue

            # Build rich text content for embedding
            text = (
                f"Rule ID: {rule_id}\n"
                f"Rule Name: {rule_name}\n"
                f"Severity: {severity}\n"
                f"Category: {category}\n"
                f"Description: {description}\n"
                f"Remediation: {remediation}\n"
            )

            documents.append({
                "id": f"rule_{rule_id.lower().replace('-', '_')}",
                "content": text,
                "metadata": {
                    "source": "openShield_rule",
                    "rule_id": rule_id,
                    "rule_name": rule_name,
                    "severity": severity,
                    "category": category,
                    "file": rule_file.name,
                },
            })

            logger.debug("Loaded rule: %s", rule_id)

        except Exception as exc:
            logger.error("Failed to load rule %s: %s", rule_file.name, exc)

    logger.info("Loaded %d rule documents", len(documents))
    return documents


def load_compliance_documents() -> List[Dict[str, Any]]:
    """
    Load all compliance framework controls as documents.

    Returns:
        List of document dicts with content and metadata.
    """
    documents = []

    for framework_name, filepath in COMPLIANCE_FILES.items():
        if not filepath.exists():
            logger.warning("Compliance file not found: %s", filepath)
            continue

        try:
            with open(filepath, encoding="utf-8") as f:
                data = json.load(f)

            framework_version = data.get("version", "")
            controls = data.get("controls", {})

            for rule_id, control in controls.items():
                control_id = control.get("control_id", "")
                control_name = control.get("control_name", "")
                description = control.get("description", "")

                text = (
                    f"Framework: {framework_name}\n"
                    f"Version: {framework_version}\n"
                    f"Rule ID: {rule_id}\n"
                    f"Control ID: {control_id}\n"
                    f"Control Name: {control_name}\n"
                    f"Description: {description}\n"
                )

                documents.append({
                    "id": f"compliance_{framework_name.lower().replace(' ', '_')}_{rule_id.lower().replace('-', '_')}",
                    "content": text,
                    "metadata": {
                        "source": "compliance_framework",
                        "framework": framework_name,
                        "framework_version": framework_version,
                        "rule_id": rule_id,
                        "control_id": control_id,
                        "control_name": control_name,
                    },
                })

            logger.info(
                "Loaded %d controls from %s", len(controls), framework_name
            )

        except Exception as exc:
            logger.error(
                "Failed to load compliance file %s: %s", filepath, exc
            )

    logger.info("Loaded %d compliance documents total", len(documents))
    return documents


def load_all_documents() -> List[Dict[str, Any]]:
    """
    Load all OpenShield documents — rules and compliance frameworks.

    Returns:
        Combined list of all document dicts.
    """
    rules = load_rule_documents()
    compliance = load_compliance_documents()
    all_docs = rules + compliance
    logger.info("Total documents loaded: %d", len(all_docs))
    return all_docs


# ------------------------------------------------------------------ #
# Private helpers                                                      #
# ------------------------------------------------------------------ #

def _extract_string(content: str, key: str) -> str:
    """Extract a simple string constant from Python source."""
    for line in content.splitlines():
        line = line.strip()
        if line.startswith(f"{key} ="):
            parts = line.split("=", 1)
            if len(parts) == 2:
                value = parts[1].strip().strip('"').strip("'")
                return value
    return ""


def _extract_multiline(content: str, key: str) -> str:
    """Extract a multi-line string constant from Python source."""
    lines = content.splitlines()
    result = []
    inside = False

    for line in lines:
        stripped = line.strip()
        if stripped.startswith(f"{key} = ("):
            inside = True
            continue
        if inside:
            if stripped == ")":
                break
            result.append(stripped.strip('"').strip("'"))

    return " ".join(result).strip()
