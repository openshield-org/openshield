# Validation Test Results

This file tracks manual validation status for scanner and low-cost Azure
scenario tests.

No tests have been executed as part of this documentation update. Every result
starts as `Pending`.

## Validation Status Tracking

| Area | Status | Notes |
|---|---|---|
| Scanner entry point documented | Pending | Documentation exists; execution not yet validated |
| Rule loading behavior documented | Pending | Documentation exists; execution not yet validated |
| Rule metadata matrix verified from files | Pending | Rule IDs are listed from current files; no runtime validation claimed |
| Storage scenario execution | Pending | Not yet executed |
| Network scenario execution | Pending | Not yet executed |
| Key Vault scenario execution | Pending | Not yet executed |
| Database persistence confirmation | Pending | Not yet executed |
| API response confirmation | Pending | Not yet executed |
| Frontend display confirmation | Pending | Not yet executed |
| Cleanup confirmation | Pending | Not yet executed |

## Environment

Fill this section during manual validation. Do not add real secrets or
sensitive identifiers.

| Field | Value |
|---|---|
| Tester | Pending |
| Date | Pending |
| OpenShield branch or commit | Pending |
| Azure subscription type | Pending |
| Azure region | Pending |
| Validation resource group | Pending |
| Authentication method | Pending |
| Database used for persistence check | Pending |
| API base URL for API check | Pending |
| Frontend URL for display check | Pending |

## Pre-Test Checklist

| Check | Status | Notes |
|---|---|---|
| Azure CLI authenticated to the intended test subscription | Pending |  |
| No production subscription selected | Pending |  |
| Validation resource group name chosen | Pending |  |
| Unique suffix chosen for global resource names | Pending |  |
| Estimated resource cost reviewed | Pending |  |
| Cleanup command reviewed | Pending |  |
| OpenShield dependencies installed locally | Pending |  |
| `AZURE_SUBSCRIPTION_ID` set locally, not committed | Pending |  |
| No secrets added to repository files | Pending |  |

## Scenario Results

| Test ID | Expected Rule | Scanner Result | Database Result | API Result | Frontend Result | Cleanup Result | Overall Status | Notes |
|---|---|---|---|---|---|---|---|---|
| `VAL-STOR-001` | `AZ-STOR-001` | Pending | Pending | Pending | Pending | Pending | Pending | Storage public blob access |
| `VAL-NET-001` | `AZ-NET-001` | Pending | Pending | Pending | Pending | Pending | Pending | NSG open SSH |
| `VAL-NET-002` | `AZ-NET-002` | Pending | Pending | Pending | Pending | Pending | Pending | NSG open RDP |
| `VAL-KV-002` | `AZ-KV-002` | Pending | Pending | Pending | Pending | Pending | Pending | Key Vault public network access |
| `VAL-KV-004` | `AZ-KV-004` | Pending | Pending | Pending | Pending | Pending | Pending | Key Vault purge protection disabled |

## Evidence Checklist

Record evidence without adding secrets, access tokens, real tenant IDs, or
other sensitive identifiers.

| Evidence Item | Status | Notes |
|---|---|---|
| Scanner command recorded | Pending |  |
| Scanner output captured with expected `rule_id` | Pending |  |
| Scanner output contains expected validation resource name | Pending |  |
| Finding severity matches expected severity | Pending |  |
| Finding category matches current scanner output | Pending |  |
| Finding persisted to PostgreSQL | Pending |  |
| API response includes expected finding | Pending |  |
| Frontend displays expected finding | Pending |  |
| Remediation guidance visible | Pending |  |
| Cleanup command executed | Pending |  |
| Resource group deletion confirmed | Pending |  |

## Failure And Investigation Log

Use this section to track failed or inconclusive validation. Do not mark a
scenario as passed until the expected rule appears and cleanup is confirmed.

| Date | Test ID | Issue Type | Description | Follow-Up Owner | Status |
|---|---|---|---|---|---|
| Pending | Pending | False positive / false negative / cleanup / permissions / other | Pending | Pending | Pending |

## Issue Type Definitions

- False positive: OpenShield reports a finding when the resource is expected
  to be compliant.
- False negative: OpenShield does not report the expected finding for an
  intentionally vulnerable resource.
- Cleanup issue: Validation resources could not be deleted or remain in a
  soft-deleted state.
- Permission issue: The scanner could not read the resource or tenant setting
  required for the rule.
- Other: Any result that does not fit the categories above.

## Post-Test Checklist

| Check | Status | Notes |
|---|---|---|
| Validation resource group deleted or deletion started | Pending |  |
| No unexpected resources left behind | Pending |  |
| Key Vault soft-delete state reviewed if applicable | Pending |  |
| No credentials written to docs or logs committed to git | Pending |  |
| Results updated without claiming unverified pass status | Pending |  |
