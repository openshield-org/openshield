# OpenSSF Silver Evidence Register

This register supports issue #199 and the official OpenSSF assessment. It is an
audit aid, not a badge claim. The BadgeApp owner must review every answer and
submit the public URL or justification.

## Ready for evidence review

| Criterion | Public evidence |
|---|---|
| `achieve_passing` | README badge and official project record |
| `contribution_requirements` | `CONTRIBUTING.md` |
| `governance` | `GOVERNANCE.md` |
| `code_of_conduct` | `.github/CODE_OF_CONDUCT.md` |
| `roles_responsibilities` | `GOVERNANCE.md`, `MAINTAINERS.md`, `.github/CODEOWNERS` |
| `documentation_roadmap` | `ROADMAP.md` |
| `documentation_architecture` | `docs/architecture.md` |
| `documentation_security` | `docs/security-requirements.md` |
| `documentation_quick_start` | README Quick Start |
| `documentation_current` | Corrected rule counts and support documentation in issue #199 PR |
| `documentation_achievements` | README Security Assurance section |
| `maintenance_or_update` | `SUPPORT.md`, `CHANGELOG.md`, database migration documentation |
| `report_tracker` | Public GitHub Issues |
| `vulnerability_response_process` | `.github/SECURITY.md` |
| `vulnerability_report_credit` | `SECURITY_ACKNOWLEDGEMENTS.md`; currently N/A because no external disclosure is recorded |
| `coding_standards` | `CONTRIBUTING.md` |
| `coding_standards_enforced` | Ruff/ESLint jobs in `.github/workflows/ci.yml` |
| `installation_common` | README Docker and source installation instructions |
| `installation_development_quick` | `CONTRIBUTING.md` Local Dev Setup |
| `external_dependencies` | `requirements.txt` and npm lockfiles |
| `dependency_monitoring` | Dependabot, Dependency Review, pip-audit and Trivy workflows |
| `updateable_reused_components` | Pinned dependency manifests and standard package managers |
| `automated_integration_testing` | GitHub Actions CI on every pull request |
| `test_statement_coverage80` | CI `--cov-fail-under=80` plus targeted Azure client tests |
| `test_policy_mandated` | Governance change process and contribution requirements |
| `tests_documented_added` | `CONTRIBUTING.md` pull-request requirements |
| `warnings_strict` | Ruff/ESLint zero-error CI gates |
| `implement_secure_design` | Security requirements and assurance case |
| `crypto_weaknesses` | Production JWT secret validation and standard maintained TLS clients |
| `crypto_credential_agility` | Runtime environment configuration without recompilation |
| `crypto_used_network` | HTTPS deployments and secure provider endpoints |
| `crypto_tls12` | Hosted HTTPS endpoints and maintained TLS libraries |
| `crypto_certificate_verification` | Standard verification defaults; no disabled verification in source |
| `crypto_verification_private` | Verification occurs in the TLS client before HTTP data is sent |
| `hardening` | Website/frontend CSP and security headers, production fail-closed configuration |
| `assurance_case` | `docs/security-assurance-case.md` |
| `static_analysis_common_vulnerabilities` | CodeQL, Bandit and Semgrep |
| `dynamic_analysis_unsafe` | N/A: project code is Python/JavaScript, not C/C++ |

## Owner or operational confirmation required

| Criterion | Required confirmation/action |
|---|---|
| `dco` | Project lead approves DCO policy and enables the merge check |
| `access_continuity` | Confirm two people hold real issue, merge, release and recovery capability |
| `bus_factor` | Confirm capability is distributed, not only documented in CODEOWNERS |
| `signed_releases` | Select and operate the signing/attestation process in `docs/release-security.md` |
| `version_tags_signed` | Create future important tags as signed annotated tags or approve equivalent attestation |
| `vulnerability_report_credit` | Confirm the acknowledgement record is complete before selecting N/A |

## Evidence or implementation still incomplete

| Criterion | Gap |
|---|---|
| `accessibility_best_practices` | Policy exists; complete keyboard/semantic/WCAG review and record results |
| `internationalization` | English-only UI; implement localization or mark Unmet with justification |
| `regression_tests_added50` | Preliminary audit shows 9 of 12 fixes with test changes; verify behavioral assertions before marking Met |
| `interfaces_current` | Review deprecated API warnings and document the periodic check |
| `input_validation` | Complete route-by-route allowlist audit and close discovered gaps |
| `crypto_algorithm_agility` | Review JWT and signing algorithm agility; document supported migration path |
| `build_repeatable` | Demonstrate repeatable frontend/release output or provide an accurate scripting-language N/A rationale |

## Likely N/A after owner review

- `sites_password_security`: OpenShield does not operate its own external-user
  password database; authentication uses JWT/deployment identity mechanisms.
- `build_standard_variables`, `build_preserve_debug`, and
  `build_non_recursive`: no native C/C++ build is produced.
- `installation_standard_variables`: source/container deployment does not use a
  system-wide POSIX installer or `DESTDIR` installation step.

N/A answers must explain the actual architecture. They must not be used to hide
missing work.
