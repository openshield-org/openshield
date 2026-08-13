# Enterprise Security Operations Rules

Issue #262 adds logging, Microsoft Defender for Cloud, and Microsoft Sentinel operational-health
controls. The foundation phase established policy and evidence collection without inventing
organisation-specific security requirements; this phase adds the ten evaluation rules built on
top of that foundation.

## Coverage

| Rule | Control |
|---|---|
| `AZ-SECOPS-001` | Subscription activity log not exported to an approved central destination |
| `AZ-SECOPS-002` | Required activity-log categories missing from the central export |
| `AZ-SECOPS-003` | Critical resource missing required diagnostic settings |
| `AZ-SECOPS-004` | Security logs have insufficient retention |
| `AZ-SECOPS-005` | Security logs stored only in a destination modifiable by workload administrators |
| `AZ-SECOPS-006` | Required Microsoft Defender for Cloud plan not enabled |
| `AZ-SECOPS-007` | High-risk Defender recommendation unresolved beyond SLA |
| `AZ-SECOPS-008` | Required Microsoft Sentinel data connector disconnected or unhealthy |
| `AZ-SECOPS-009` | Sentinel missing required high-severity analytics coverage |
| `AZ-SECOPS-010` | Security alerts have no monitored incident-response destination |

## Policy boundary

`config/security-operations-policy.example.json` documents every value that an organisation must
approve: critical resource types, central destinations, activity-log categories, retention,
Defender plans and SLA, Sentinel connectors and analytics coverage, and exclusions. The example is
not a production baseline and is never loaded automatically.

Every AZ-SECOPS rule reads its policy from the file named by the
`OPENSHIELD_SECURITY_OPERATIONS_POLICY` environment variable. If the variable is unset, the
referenced file is missing, or the file fails `load_security_operations_policy`'s strict
validation, the rule logs a warning and returns no findings — an unapproved policy can never
produce a compliance claim in either direction. Operators must set this variable to their
organisation's own policy file (never the example file) before running these ten rules.

## Sentinel scope: auto-discovered, not configured

Microsoft Sentinel workspace scope is **discovered at scan time**, not named in the policy file.
Every Log Analytics workspace in the subscription is enumerated
(`LogAnalyticsManagementClient.workspaces.list()`, genuinely subscription-wide), and each
workspace's Sentinel onboarding state is checked individually
(`SecurityInsights.sentinel_onboarding_states.list(resource_group, workspace_name)`, which is not
subscription-wide — Sentinel's SDK requires a resource group and workspace name for every
operation). Only workspaces confirmed onboarded are queried for data connectors, analytics rules,
and automation rules. This means a newly onboarded Sentinel workspace is covered automatically on
the next scan with no policy change required.

## Outcome model

Issue #262 requires a four-state PASS/FAIL/UNKNOWN/NOT_APPLICABLE outcome per control, but
`scanner/engine.py` only consumes a findings list and treats *presence of a finding* as the sole
non-compliance signal (it feeds the list directly into severity-weighted scoring). All ten rules
therefore represent the outcomes as follows, matching the existing convention already used by
`az_dl_001`/`az_dl_002` and `az_kv_003`:

- **PASS** — an empty list. No finding is emitted for a compliant resource.
- **NOT_APPLICABLE** — an empty list plus an `INFO`-level log line (e.g. no critical resources in
  scope, no Sentinel-onboarded workspaces, no required plans/connectors/analytics configured).
- **UNKNOWN** — an empty list plus a `WARNING`-level log line. Any collector failure — a missing
  policy, a permission error, an inaccessible workspace, a failed Defender/Sentinel API call — is
  UNKNOWN and is never promoted to FAIL or silently treated as PASS.
- **FAIL** — the only outcome that produces a finding dict, and only with positive evidence of a
  missing or unsafe control (e.g. an actual diagnostic setting missing an approved destination, an
  actual disabled Defender plan, an actual disconnected connector).

This is a real, structural limitation of the current engine contract: NOT_APPLICABLE and UNKNOWN
are not individually addressable as distinct dict rows the way FAIL findings are. The richer
per-finding metadata issue #262 also asks for — scope, category, destination, retention,
ownership, evidence timestamp, remediation, permissions required, severity, confidence, and an
`unknown_reason` field — is carried on every FAIL finding's `metadata` dict so downstream tooling
can still see "why," even though that metadata cannot currently attach to an outcome that produces
no finding at all. Changing `engine.py`'s contract to add first-class UNKNOWN/NOT_APPLICABLE rows
was out of scope for this change and would affect every existing rule, not just these ten.

## Rule details

### AZ-SECOPS-001 — Subscription activity log not exported

Checks the subscription's `subscription_diagnostic_settings` for at least one setting whose
`workspace_id`, `storage_account_id`, or `event_hub_authorization_rule_id` matches
`approved_destination_ids`. No approved-destination match is a HIGH finding.

### AZ-SECOPS-002 — Required activity-log categories missing

Given at least one approved-destination export exists (otherwise AZ-SECOPS-001 owns the finding),
checks that every category in `required_activity_categories` appears as an *enabled* `LogSettings`
entry on an approved-destination setting. A disabled category counts as missing.

### AZ-SECOPS-003 — Critical resource missing required diagnostic settings

For every resource ID returned by `critical_resource_ids(policy)` (minus `approved_exclusions`),
checks `resource_diagnostic_settings` for at least one setting reaching an approved destination.

### AZ-SECOPS-004 — Security logs have insufficient retention

For each critical resource's diagnostic settings that target a Storage Account destination,
checks that every enabled log's `retention_policy` is enabled with `days >= minimum_retention_days`.
Log Analytics workspace retention is a workspace-level setting, not a `retention_policy` field on
the diagnostic setting, and is intentionally out of scope for this rule.

### AZ-SECOPS-005 — Security logs stored only in a workload-administrator-modifiable destination

For each critical resource with a diagnostic export that is **not** on the approved-destination
list, checks whether every configured destination's resource group matches the workload resource's
own resource group. If so, an administrator with Contributor/Owner on that resource group can
modify or delete the exported logs. This is a resource-group/ownership comparison — the Monitor
diagnostic-settings API does not expose a destination's own access-control or immutability
configuration, so this rule cannot verify an actual Storage immutability policy directly.

### AZ-SECOPS-006 — Required Defender for Cloud plan not enabled

Checks `Microsoft.Security/pricings` (subscription scope) for each plan named in
`required_defender_plans`; a plan whose `pricing_tier` is not `Standard` is a HIGH finding. Each
finding records the matching CIS Azure Foundations Benchmark leaf control for that specific plan
(e.g. 2.1.7 for StorageAccounts) in `metadata.cis_control_reference`, since the rule itself is
policy-driven across whichever plans the organisation names and has no single fixed CIS mapping.

### AZ-SECOPS-007 — High-risk Defender recommendation unresolved beyond SLA

Checks `Microsoft.Security/assessments` for entries with `metadata.severity == High` and
`status.code == Unhealthy`. Age is computed from a first-observed timestamp read defensively from
the assessment's `additional_data` map (the SDK's typed `AssessmentStatusResponse` model exposes
no timestamp field at all). An assessment with no recognised timestamp key is excluded from this
rule's findings — its age is genuinely unknown and is never assumed to be either compliant or
overdue.

### AZ-SECOPS-008 — Required Sentinel data connector disconnected or unhealthy

For each Sentinel-onboarded workspace, checks `data_connectors.list` for every connector kind in
`required_sentinel_connectors`. A connector is "connected" when present with at least one enabled
`data_types` entry (or when its connector kind exposes no typed `data_types` field at all, in
which case presence is the only available signal). Missing or fully-disabled connectors are HIGH
findings, distinguished as `missing` vs. `disconnected` in `metadata.connector_state`.

### AZ-SECOPS-009 — Sentinel missing required high-severity analytics coverage

For each Sentinel-onboarded workspace, checks `alert_rules.list` for an **enabled** scheduled rule
with `severity == High` whose `display_name` matches (case/separator-insensitive substring) each
use case in `required_high_severity_analytics`. A disabled rule, a wrong-severity rule, or no
matching rule at all is a HIGH finding.

### AZ-SECOPS-010 — Security alerts have no monitored incident-response destination

Checks Azure Monitor `action_groups.list_by_subscription_id()` for at least one **enabled** action
group with at least one receiver (email, SMS, voice, webhook, ITSM, Logic App, Automation
runbook, Azure Function, or Event Hub). If none exists, checks whether any Sentinel-onboarded
workspace has at least one automation rule (Sentinel's native incident-routing mechanism,
typically a `RunPlaybook` action) as an accepted alternative destination. Only when *neither*
mechanism exists is this a HIGH finding.

## Collection behavior

- Collection is read-only and retrieves configuration metadata only, never log, alert, or incident
  content.
- A successful empty response is `COMPLETE` with no items.
- Permission, API, or transport failures are `FAILED`; they are never converted into an empty
  inventory or compliance claim.
- Sentinel's per-workspace fan-out (onboarding checks, data connectors, alert rules, automation
  rules) uses a third `PARTIAL` `CollectionStatus`: when some workspaces succeed and others fail,
  the succeeded workspaces' evidence is still usable and the failed workspaces are listed in
  `CollectionResult.failed_scopes` so rules can treat only the affected scope as UNKNOWN rather than
  discarding evidence for every other workspace in the subscription.
- Resource diagnostic settings are collected only for policy-scoped critical resource IDs.

## Minimum Azure permissions

- `Microsoft.Insights/diagnosticSettings/read` — activity-log and resource diagnostic settings
  (AZ-SECOPS-001 through 005).
- `Microsoft.Insights/actionGroups/read` — action group inventory (AZ-SECOPS-010).
- `Microsoft.Security/pricings/read` — Defender plan pricing tier (AZ-SECOPS-006).
- `Microsoft.Security/assessments/read` — Defender recommendations (AZ-SECOPS-007).
- `Microsoft.OperationalInsights/workspaces/read` — Log Analytics workspace enumeration used for
  Sentinel auto-discovery.
- `Microsoft.SecurityInsights/onboardingStates/read`, `.../dataConnectors/read`,
  `.../alertRules/read`, `.../automationRules/read` — Sentinel workspace and content collection
  (AZ-SECOPS-008, 009, 010).
- Read access to the resource inventory used to select critical resources.

No remediation or write permission is required by any of these ten rules; the accompanying
`playbooks/cli/fix_az_secops_*.sh` scripts run separately under an operator identity.

## References

- [CIS Microsoft Azure Foundations Benchmark v2.0.0](https://www.cisecurity.org/benchmark/azure)
- [Azure Monitor diagnostic settings](https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings)
- [Azure Activity Log](https://learn.microsoft.com/azure/azure-monitor/essentials/activity-log)
- [Microsoft Defender for Cloud pricing](https://learn.microsoft.com/azure/defender-for-cloud/pricing)
- [Microsoft Defender for Cloud recommendations](https://learn.microsoft.com/azure/defender-for-cloud/review-security-recommendations)
- [Microsoft Sentinel data connectors](https://learn.microsoft.com/azure/sentinel/data-connectors-reference)
- [Microsoft Sentinel automation rules](https://learn.microsoft.com/azure/sentinel/automate-incident-handling-with-automation-rules)
- [Azure Monitor action groups](https://learn.microsoft.com/azure/azure-monitor/alerts/action-groups)
