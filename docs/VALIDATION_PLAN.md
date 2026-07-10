# OpenShield Validation Plan

This document defines the validation approach for OpenShield scanner behavior
and controlled Azure vulnerable scenarios. It is a planning document only. It
does not record completed validation and does not require real Azure validation
to run automatically in CI.

All current test execution results are `Pending`.

## Purpose

The validation effort is intended to prove that OpenShield findings can move
through the product lifecycle in a reliable, contributor-verifiable way:

1. The scanner detects an Azure misconfiguration.
2. The scan result can be persisted to PostgreSQL by the platform.
3. The Flask API can expose the persisted finding through the expected
   endpoints.
4. The React frontend can display the issue and remediation guidance.

The first version focuses on scanner validation and real Azure scenario
planning. It does not attempt to validate every rule at once.

## Scope

In scope:

- Scanner entry point and rule-loading behavior.
- Rule metadata and finding shape validation.
- Low-cost Azure vulnerable scenario planning.
- Manual test result tracking.
- Cleanup and risk documentation for contributor-run validation.

Out of scope for this documentation pass:

- Frontend implementation changes.
- API implementation changes.
- Database schema changes.
- Real Azure CI automation.
- Credential, secret, or tenant-specific setup.
- Expensive Azure resource creation.

## Validation Principles

Validation should follow the same lifecycle that production data follows.

### 1. Scanner

The scanner is the first source of truth. A scenario is not considered valid
unless the expected rule produces a finding with the correct `rule_id`,
resource identity, severity, category, and remediation metadata.

### 2. Database

Findings should persist after a scan is triggered through the platform path.
Database validation should confirm that scan metadata and finding rows are
stored without changing the finding semantics produced by the scanner.

### 3. API

API validation should confirm that the persisted finding is available through
the expected read endpoints. Response payloads should preserve the rule ID,
resource name, resource ID, severity, category, description, remediation, and
playbook references needed by the dashboard.

### 4. Frontend

Frontend validation should confirm that the issue is visible to a user and
that remediation guidance can be reached from the dashboard. The frontend is
validated as a consumer of scanner/API data; this plan does not require
frontend source edits.

## Phased Validation

### Phase 1: Storage and Network

Goal: Validate low-cost, easy-to-clean scenarios that are realistic in an Azure
Student subscription.

Initial rules:

- `AZ-STOR-001`: Public Blob Access Enabled on Storage Account
- `AZ-NET-001`: NSG Allows Unrestricted Inbound SSH from Any Source
- `AZ-NET-002`: NSG Allows Unrestricted Inbound RDP from Any Source

### Phase 2: Key Vault and Identity

Goal: Add Key Vault checks and identify which identity checks are safe to test
without tenant-wide risk.

Initial Key Vault rules:

- `AZ-KV-002`: Key Vault Allows Public Network Access Without Private Endpoint
- `AZ-KV-004`: Key Vault Purge Protection Disabled

Identity rules should be reviewed individually because several require
Microsoft Graph or tenant-level permissions.

### Phase 3: Database and Compute

Goal: Add database and compute scenarios only after Phase 1 cleanup and
evidence collection are reliable.

Database and compute resources may create more cost, quota, or cleanup risk
than Phase 1 resources. Each scenario must include a cost and cleanup review
before execution.

### Phase 4: Full Rule Coverage

Goal: Build toward full rule coverage after the low-cost path is proven.

This phase should classify each rule as one of:

- Safe for student subscription validation.
- Maintainer-only validation.
- Mock-only validation.
- Not safe or not practical to validate with real resources.

## Non-Goals

- Do not add Azure credentials or real subscription identifiers to the repo.
- Do not create expensive Azure resources as part of this plan.
- Do not run real Azure validation automatically in pull request CI.
- Do not claim validation has passed until results are manually recorded.
- Do not delete broad subscription resources during cleanup.

## Documentation Map

- `docs/validation/SCANNER_VALIDATION.md`: scanner entry point, rule format,
  verified rule matrix, and scanner-specific notes.
- `docs/validation/AZURE_SCENARIOS.md`: low-cost vulnerable Azure scenario
  plan with cleanup commands.
- `docs/validation/TEST_RESULTS.md`: manual status tracker and result
  template. All rows start as `Pending`.
