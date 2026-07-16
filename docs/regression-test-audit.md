# Regression Test Audit

OpenShield requires reproducible bug fixes to include automated regression
tests. This audit covers merged bug-fix pull requests from the project's start
through 16 July 2026, within the six-month OpenSSF Silver review window.

The audit searched merged pull requests whose title identified a fix and checked
whether the pull request changed a file under `tests/` or another automated test
file. Release-only aggregation PRs were not counted as individual bug fixes.

| Pull request | Automated test changed? |
|---|---|
| #108 scanner abstraction fix | No |
| #130 compliance mapping fix | No |
| #143 Flask test-safety/CI fix | No separate regression file |
| #145 latest-scan endpoint fix | Yes |
| #162 reliability fixes | Yes |
| #166 compliance, TLS and pagination fixes | Yes |
| #169 async scan recovery fix | Yes |
| #175 container vulnerability fix | Yes |
| #183 CodeQL security fixes | Yes |
| #184 identity logging fix | Yes |
| #185 Semgrep workflow fixes | Yes |
| #188 XSS and AI-key fixes | Yes |

Nine of twelve audited bug-fix pull requests changed automated tests: **75% by
file-change evidence**. This is above the Silver 50% threshold, subject to a
maintainer confirming that the changed tests reproduce the corrected behavior.

This preliminary repository-history audit is not a claim that every test fully
exercises every fixed behavior. Maintainers must verify the behavioral
assertions before entering this criterion as Met, and refresh the audit before
each OpenSSF assessment.
