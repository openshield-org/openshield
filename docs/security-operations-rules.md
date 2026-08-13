# Enterprise Security Operations Rules

Issue #262 adds logging, Defender for Cloud, and Microsoft Sentinel controls. The first implementation phase establishes policy and evidence collection without inventing organisation-specific security requirements.

## Policy boundary

`config/security-operations-policy.example.json` documents every value that an organisation must approve: critical resource types, central destinations, activity-log categories, retention, Defender plans and SLA, Sentinel connectors and analytics coverage, and exclusions. The example is not a production baseline and is never loaded automatically.

## Collection behavior

- Collection is read-only and retrieves configuration metadata only, never log or alert content.
- A successful empty response is `COMPLETE` with no items.
- Permission, API, or transport failures are `FAILED`; they are never converted into an empty inventory or compliance claim.
- Resource diagnostic settings are collected only for policy-scoped critical resource IDs.
- Final `PASS`, `FAIL`, `ERROR`, and `NOT_APPLICABLE` evaluation will integrate with issue #263 rather than creating a second outcome model.

## Minimum Azure permissions

- `Microsoft.Insights/diagnosticSettings/read`
- `Microsoft.Insights/eventtypes/values/read` where activity-log metadata is required
- Read access to the resource inventory used to select critical resources

Defender and Sentinel permissions will be added with their dedicated collectors. No remediation or write permission is introduced in this phase.
