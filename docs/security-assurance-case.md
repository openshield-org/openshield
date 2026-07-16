# OpenShield Security Assurance Case

## Claim

When deployed according to the documented production requirements, OpenShield
provides a defensible, least-privilege Azure configuration assessment without
intentionally collecting workload secrets or contents. This claim is bounded by
the limitations in `docs/security-requirements.md`.

## Assets and threats

Protected assets include Azure credentials, JWT signing material, scan results,
resource metadata, database records, remediation authority and release
integrity. Relevant threat actors include unauthenticated internet clients,
malicious or compromised contributors, compromised dependencies, overprivileged
cloud identities, malicious insiders and attackers controlling Azure API data.

Primary threats are unauthorized scan execution or data modification, secret
disclosure, injection, path traversal, server-side request abuse, forged tokens,
unsafe remediation, dependency compromise, false compliance and tampered
releases.

## Trust boundaries

```text
Browser ──HTTPS──> Frontend ──HTTPS──> Flask API ──> PostgreSQL
                                      │
                                      ├──> Azure management APIs / Graph
                                      ├──> NVD and configured AI providers
                                      └──> optional Sentinel ingestion

Contributor ──pull request──> GitHub review and CI ──> protected project code
Operator ──explicit confirmation──> remediation playbook ──> Azure resource
```

Data crossing each boundary is untrusted until authenticated and validated.
Azure and third-party API responses are also treated as potentially malformed
or incomplete.

## Secure design argument

- **Least privilege:** CI permissions are scoped per workflow; Azure checks use
  management metadata and document minimum read permissions.
- **Fail-safe defaults:** production rejects weak JWT configuration; API or
  permission failures do not silently become compliant results.
- **Complete mediation:** protected write routes apply authentication centrally.
- **Separation of privilege:** changes require review and CI; destructive
  remediation requires explicit operator confirmation; security disclosures use
  a private process.
- **Economy of mechanism:** scanner rules use a shared Azure client and normalized
  finding schema rather than embedding credentials or clients in every rule.
- **Open design:** policies, source, workflows, tests and security evidence are
  public and reviewable.
- **Minimize sensitive data:** findings contain the configuration context needed
  for remediation, not secrets or customer workload contents.

## Implementation weakness argument

- Injection and malformed input are countered with typed JSON handling,
  allowlist validation, path normalization and tests for security boundaries.
- Authentication weaknesses are countered by production secret validation,
  token verification and protected state-changing routes.
- Supply-chain risks are countered by pinned GitHub Actions, dependency review,
  pip-audit, Dependabot, SBOM generation, Trivy and release review.
- Code weaknesses are checked using Ruff, CodeQL, Bandit, Semgrep, Gitleaks and
  automated regression tests.
- Browser risks are reduced by CSP and other security headers on deployed web
  surfaces.
- Availability risks from remediation are reduced through validation, warnings
  and explicit confirmation rather than automatic changes.

## Residual risk and evidence review

Cloud APIs can change, checks can be incomplete, mappings can be contextual, and
maintainers or dependencies can be compromised. Findings therefore support—not
replace—professional risk assessment. Evidence is reviewed through CI, release
work, security advisories and the OpenSSF assessment. Gaps remain tracked in
issue #199 until the project can support each claim with current public proof.
