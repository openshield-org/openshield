name: Feature Request
about: Suggest a new rule, compliance mapping, playbook, or capability for OpenShield
title: "feat: "
labels: enhancement
assignees: ''
---

## Summary

A clear one-sentence description of the feature you are proposing.

## Problem It Solves

What is the current limitation or gap? Why does this matter for Azure cloud security posture?
Link any related issues or discussions if relevant.

## Proposed Solution

Describe what you want to happen. Be specific.

---

**If proposing a new scanner rule, fill in all fields below:**

- Azure resource type:
- Misconfiguration it detects:
- Suggested RULE_ID (format: `AZ-<SERVICE>-<NNN>`, e.g. `AZ-KV-003`):
- Severity: (CRITICAL / HIGH / MEDIUM / LOW)
- Compliance frameworks it maps to:
  - CIS Azure Benchmark control:
  - NIST CSF control:
  - ISO 27001 control:
- Does a matching remediation playbook need to be created? (Yes / No)

---

**If proposing a compliance mapping:**

- Framework name and version:
- Control ID(s):
- Which existing rules does it apply to:
- Source documentation link:

---

**If proposing an API or CLI change:**

- Endpoint or command affected:
- Current behaviour:
- Proposed behaviour:
- Example request/response or command:

---

## Alternatives Considered

What other approaches did you consider, and why did you rule them out?

## Additional Context

Add any Azure documentation links, CVE references, CIS Benchmark pages, screenshots, or reference implementations here.

## Contribution

Are you willing to implement this yourself?

- [ ] Yes, I plan to open a PR for this
- [ ] I can help review a PR but cannot implement it myself
- [ ] I am not able to contribute code for this