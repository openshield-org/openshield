#!/usr/bin/env python3
"""
Script to update the OpenShield Learn page with current statistics from the codebase.
"""

import os
import re

def count_rules_and_playbooks():
    """Count the number of rules and playbooks."""
    rules_dir = 'scanner/rules'
    playbooks_dir = 'playbooks/cli'
    
    rule_count = 0
    if os.path.exists(rules_dir):
        for root, dirs, files in os.walk(rules_dir):
            for file in files:
                if file.endswith('.py') and not file.endswith('_common.py'):
                    rule_count += 1
    
    playbook_count = 0
    if os.path.exists(playbooks_dir):
        for root, dirs, files in os.walk(playbooks_dir):
            for file in files:
                if file.endswith('.sh'):
                    playbook_count += 1
    
    return rule_count, playbook_count

def count_severities():
    """Count the number of rules by severity."""
    severities = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
    rules_dir = 'scanner/rules'
    if os.path.exists(rules_dir):
        for root, dirs, files in os.walk(rules_dir):
            for file in files:
                if file.endswith('.py') and not file.endswith('_common.py'):
                    filepath = os.path.join(root, file)
                    with open(filepath, 'r') as f:
                        content = f.read()
                        # Extract SEVERITY
                        sev_match = re.search(r'SEVERITY\s*=\s*\"([^\"]+)\"', content)
                        if sev_match:
                            sev = sev_match.group(1).strip()
                            if sev in severities:
                                severities[sev] += 1
    return severities

def update_learn_page():
    """Update the learn page with current statistics."""
    learn_page_path = 'docs/learn/index.html'
    
    if not os.path.exists(learn_page_path):
        print(f"Error: {learn_page_path} not found")
        return
    
    # Read the current file
    with open(learn_page_path, 'r') as f:
        content = f.read()
    
    # Get counts
    rule_count, playbook_count = count_rules_and_playbooks()
    severities = count_severities()
    high_count = severities['HIGH']
    
    # Update the metrics section
    # Pattern for the metrics div
    metrics_pattern = r'(<div class="metrics" aria-label="OpenShield project metrics">\s*<div class="metric"><strong>)\d+(</strong><span>Azure scan rules</span></div>\s*<div class="metric"><strong>)\d+(</strong><span>CLI remediation playbooks</span></div>\s*<div class="metric"><strong>)\d+(</strong><span>Compliance frameworks</span></div>\s*<div class="metric"><strong>)\d+(</strong><span>AI security skills</span></div>\s*<div class="metric"><strong>)\d+(</strong><span>High-severity checks</span></div>\s*</div>)'
    
    # We'll do it step by step for simplicity
    # Replace Azure scan rules
    content = re.sub(r'(<div class="metric"><strong>)\d+(</strong><span>Azure scan rules</span></div>)',
                     rf'\1{rule_count}\2', content)
    # Replace CLI remediation playbooks
    content = re.sub(r'(<div class="metric"><strong>)\d+(</strong><span>CLI remediation playbooks</span></div>)',
                     rf'\1{playbook_count}\2', content)
    # Replace Compliance frameworks (still 4)
    # Replace AI security skills (still 8)
    # Replace High-severity checks
    content = re.sub(r'(<div class="metric"><strong>)\d+(</strong><span>High-severity checks</span></div>)',
                     rf'\1{high_count}\2', content)
    
    # Update the pipeline step
    content = re.sub(r'(<div class="pipeline-step"><strong>Rule Evaluation</strong><span>)\d+( dynamic checks</span></div>)',
                     rf'\1{rule_count}\2', content)
    
    # Update the rules section title and intro
    # First, the title
    content = re.sub(r'(<h2 class="section-title">)\d+( Azure security rules</h2>)',
                     rf'\1{rule_count}\2', content)
    # Then the intro paragraph
    content = re.sub(r'(<p class="section-intro">\s*OpenShield currently has )\d+( dynamic rules\. The strongest contributor work improves rule accuracy, reduces false positives,)',
                     rf'\1{rule_count}\2', content)
    
    # Write back
    with open(learn_page_path, 'w') as f:
        f.write(content)
    
    print(f"Updated {learn_page_path}")
    print(f"Rules: {rule_count}, Playbooks: {playbook_count}, High severity: {high_count}")

if __name__ == '__main__':
    update_learn_page()