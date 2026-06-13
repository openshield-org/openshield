"""
Document loader for OpenShield rules and compliance frameworks.
Loads scanner rules, CIS, NIST, ISO 27001 and SOC2 controls
into structured documents ready for chunking and embedding.
"""

import json
import logging
import re
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


def load_skill_documents() -> List[Dict[str, Any]]:
    """
    Load Claude-Red AI skills from markdown files.
    Injects relevant OpenShield scanner rules based on tags and mapping.

    Returns:
        List of document dicts with content and metadata.
    """
    documents = []
    skills_dir = PROJECT_ROOT / "ai" / "knowledge" / "skills"
    mapping_file = PROJECT_ROOT / "ai" / "knowledge" / "rule_mapping.json"

    if not skills_dir.exists():
        logger.warning("Skills directory not found: %s", skills_dir)
        return documents

    # Load mapping registry
    mapping = {}
    if mapping_file.exists():
        try:
            with open(mapping_file, "r") as f:
                mapping = json.load(f)
        except Exception as exc:
            logger.error("Failed to load rule_mapping.json: %s", exc)

    # Pre-load all rule IDs and names grouped by category for quick lookup
    all_rules = load_rule_documents()
    rules_by_category = {}
    for rule in all_rules:
        cat = rule["metadata"].get("category")
        if cat:
            rules_by_category.setdefault(cat, []).append(
                f"- `{rule['metadata']['rule_id']}`: {rule['metadata']['rule_name']}"
            )

    for skill_file in sorted(skills_dir.rglob("*.md")):
        try:
            content = skill_file.read_text(encoding="utf-8")
            skill_name = skill_file.parent.name
            
            # Dynamic Grounding: Find relevant rules for this skill
            relevant_rules = []
            content_lower = content.lower()
            
            for category, keywords in mapping.items():
                for keyword in keywords:
                    # Use boundary-aware matching to avoid short tokens matching inside unrelated words
                    # e.g., 'vm' inside 'devmac', or 'shor' inside 'shortest'
                    pattern = r'\b' + re.escape(keyword.lower()) + r'\b'
                    if re.search(pattern, content_lower):
                        relevant_rules.extend(rules_by_category.get(category, []))
                        break # Only need one keyword match per category
            
            if relevant_rules:
                # Remove duplicates while preserving order
                unique_rules = list(dict.fromkeys(relevant_rules))
                injection = "\n\n## OpenShield Implementation Capabilities\n"
                injection += "The following automated scanner rules in OpenShield implement or detect the methodologies described above:\n\n"
                injection += "\n".join(unique_rules)
                injection += "\n\nWhen these rules trigger findings, use the investigation steps in this skill for deep-dive analysis."
                content += injection

            documents.append({
                "id": f"skill_{skill_name.lower().replace('-', '_')}",
                "content": content,
                "metadata": {
                    "source": "claude_red_skill",
                    "skill_name": skill_name,
                    "file": skill_file.name,
                },
            })

            logger.debug("Loaded grounded skill: %s", skill_name)

        except Exception as exc:
            logger.error("Failed to load skill %s: %s", skill_file.name, exc)

    logger.info("Loaded %d skill documents with dynamic grounding", len(documents))
    return documents


def load_all_documents() -> List[Dict[str, Any]]:
    """
    Load all OpenShield documents — rules, compliance, and grounded skills.

    Returns:
        Combined list of all document dicts.
    """
    rules = load_rule_documents()
    compliance = load_compliance_documents()
    skills = load_skill_documents()
    all_docs = rules + compliance + skills
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
