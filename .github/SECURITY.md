# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in OpenShield, please **do not open a public GitHub issue**.
Opening a public issue exposes the vulnerability to bad actors before a fix is available.


We will acknowledge your report within 48 hours and work with you to coordinate a fix and responsible disclosure timeline.

### What to include in your report

To help us triage quickly, please include:

- A description of the vulnerability and its potential impact
- The affected component (scanner engine, REST API, auth logic, playbooks)
- Steps to reproduce the issue
- Any relevant logs, proof-of-concept code, or screenshots
- The version of OpenShield you were testing (check `git log --oneline -1`)

The more detail you provide, the faster we can respond.

---

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

Older versions are not patched. If you are running a version below 0.1.x, upgrade to the latest release before filing a report.

---

## Disclosure Process

We follow a coordinated disclosure model:

1. **Report received** -- you email the vulnerability privately
2. **Acknowledgement** -- we respond within 48 hours to confirm receipt
3. **Investigation** -- we reproduce and assess the impact
4. **Fix developed** -- we write and test a patch
5. **Coordinated release** -- we agree a disclosure date with you (typically 7-14 days after fix)
6. **Public advisory** -- we publish a GitHub Security Advisory and release the fix

We ask that you do not publicly disclose the vulnerability until step 6 is complete.

---

## Scope

### In scope

- Scanner engine (`scanner/`) -- rule logic, Azure SDK calls, output handling
- REST API (`api/`) -- authentication, authorisation, input validation, JWT handling
- Compliance framework mappings (`compliance/`) -- data integrity
- Sentinel integration (`sentinel/`) -- HMAC signing, data upload logic
- Hardcoded secrets or credentials anywhere in the codebase

### Out of scope

- Vulnerabilities in third-party dependencies -- report those to the upstream maintainer
- Security issues in infrastructure you deploy OpenShield to (your Azure environment, your PostgreSQL instance)
- Social engineering attacks
- Physical security

---

## Recognition

We value responsible disclosure. Researchers who report valid vulnerabilities will be:

- Acknowledged by name (or pseudonym if preferred) in the release notes for the fix
- Listed in a `SECURITY_ACKNOWLEDGEMENTS.md` file we maintain in this repository

We do not currently offer a bug bounty programme, but we are grateful for every report.

---

## Contact

**Email: vishnu.ajith@owasp.org**