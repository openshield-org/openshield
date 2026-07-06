import json
import re
from pathlib import Path

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "scanner" / "rules"
MAPPING_FILE = PROJECT_ROOT / "ai" / "knowledge" / "rule_mapping.json"


def get_rule_categories():
    """Extracts all unique CATEGORY values from the Python rules."""
    categories = set()
    category_re = re.compile(r'^CATEGORY\s*=\s*["\'](.*?)["\']', re.MULTILINE)

    for rule_file in RULES_DIR.glob("az_*.py"):
        content = rule_file.read_text(encoding="utf-8")
        match = category_re.search(content)
        if match:
            categories.add(match.group(1))

    return categories


def audit_grounding():
    """Checks for inconsistencies between mapping registry and actual rules."""
    print("--- AI Grounding Audit ---")

    if not MAPPING_FILE.exists():
        print(f"Error: Mapping file {MAPPING_FILE} not found.")
        return

    with open(MAPPING_FILE, "r") as f:
        mapping = json.load(f)

    rule_categories = get_rule_categories()
    mapping_categories = set(mapping.keys())

    # Check 1: Categories in mapping but not in rules
    stale_categories = mapping_categories - rule_categories
    if stale_categories:
        print("\n[!] STALE CATEGORIES (In mapping but no rules found):")
        for cat in stale_categories:
            print(f"  - {cat}")
    else:
        print("\n[✓] No stale categories found in mapping.")

    # Check 2: Categories in rules but missing from mapping
    missing_categories = rule_categories - mapping_categories
    if missing_categories:
        print("\n[!] MISSING CATEGORIES (In rules but missing from AI mapping):")
        print("    (AI will not be able to link skills to these rules!)")
        for cat in missing_categories:
            print(f"  - {cat}")
    else:
        print("\n[✓] All rule categories are represented in the AI mapping.")

    # Check 3: Check for empty keyword lists
    empty_keywords = [cat for cat, keywords in mapping.items() if not keywords]
    if empty_keywords:
        print("\n[!] EMPTY KEYWORDS (Categories with no trigger keywords):")
        for cat in empty_keywords:
            print(f"  - {cat}")

    print("\nAudit Complete.")


if __name__ == "__main__":
    audit_grounding()
