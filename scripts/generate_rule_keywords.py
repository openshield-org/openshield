import json
import os
import sys
import re
from pathlib import Path
from api.services.ai_provider import get_completion

# Setup paths
PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "scanner" / "rules"
MAPPING_FILE = PROJECT_ROOT / "ai" / "knowledge" / "rule_mapping.json"

PROMPT_TEMPLATE = """
You are a cybersecurity expert specializing in Azure.
I am building an AI mapping registry for a security scanner.
Read the following Python code for a security scanner rule and extract 3-5 high-quality keywords or short tags.
These keywords will be used to link this rule to offensive security methodologies (skills).

RULES FOR KEYWORDS:
1. They must be lowercase.
2. They should focus on the underlying technology or vulnerability type (e.g., 'entra-id', 'sqli', 'ssrf', 'encryption').
3. Do not use generic words like 'security' or 'azure'.
4. Format the output as a comma-separated list.

RULE CODE:
{rule_code}

OUTPUT (Comma-separated keywords only):
"""

def generate_keywords(rule_path, provider, api_key):
    """Uses AI to extract keywords from a rule file."""
    content = rule_path.read_text(encoding="utf-8")
    
    # Extract only the metadata section for context efficiency
    meta_section = ""
    lines = content.splitlines()
    for line in lines:
        if any(key in line for key in ["RULE_ID", "RULE_NAME", "DESCRIPTION", "CATEGORY"]):
            meta_section += line + "\n"
            
    prompt = PROMPT_TEMPLATE.format(rule_code=meta_section)
    
    try:
        response = get_completion(provider, api_key, prompt)
        keywords = [k.strip().lower() for k in response.split(",")]
        return keywords
    except Exception as exc:
        print(f"Error generating keywords for {rule_path.name}: {exc}")
        return []

def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/generate_rule_keywords.py <rule_filename_or_all> [provider] [api_key]")
        return

    target = sys.argv[1]
    provider = sys.argv[2] if len(sys.argv) > 2 else os.getenv("AI_PROVIDER", "gemini")
    api_key = sys.argv[3] if len(sys.argv) > 3 else os.getenv("AI_API_KEY")

    if not api_key:
        print("Error: AI_API_KEY environment variable not set.")
        return

    # Load existing mapping
    with open(MAPPING_FILE, "r") as f:
        mapping = json.load(f)

    rules_to_process = []
    if target == "all":
        rules_to_process = list(RULES_DIR.glob("az_*.py"))
    else:
        rules_to_process = [RULES_DIR / target]

    for rule_file in rules_to_process:
        if not rule_file.exists():
            print(f"Skipping {rule_file.name} - not found.")
            continue

        # Get the category from the file
        category_match = re.search(r'^CATEGORY\s*=\s*["\'](.*?)["\']', rule_file.read_text(), re.M)
        if not category_match:
            print(f"Skipping {rule_file.name} - no CATEGORY found.")
            continue
            
        category = category_match.group(1)
        print(f"Processing {rule_file.name} (Category: {category})...")
        
        new_keywords = generate_keywords(rule_file, provider, api_key)
        if new_keywords:
            # Update mapping
            existing = set(mapping.get(category, []))
            updated = sorted(list(existing.union(set(new_keywords))))
            mapping[category] = updated
            print(f"  Suggested keywords: {', '.join(new_keywords)}")

    # Save updated mapping
    with open(MAPPING_FILE, "w") as f:
        json.dump(mapping, f, indent=2)
    
    print("\nMapping registry updated successfully.")

if __name__ == "__main__":
    main()
