# Enterprise App Registration and Managed Identity Rules

OpenShield evaluates Microsoft Entra App Registration configuration and correlates
managed-identity service principals with Azure subscription RBAC assignments.

## Coverage

| Rule | Control |
|---|---|
| `AZ-IDN-010` | App Registration ownership |
| `AZ-IDN-011` | Non-loopback HTTP redirect URIs |
| `AZ-IDN-012` | OAuth implicit grant |
| `AZ-IDN-013` | Password credential presence |
| `AZ-IDN-014` | Multi-tenant application-instance property lock |
| `AZ-IDN-015` | Owner/Contributor managed identity at subscription scope |

`AZ-IDN-006` continues to detect stale, expired, and non-expiring password
credentials, but now reuses the same cached application inventory.

## Required permissions

- Microsoft Graph application permission `Application.Read.All` reads App
  Registrations, minimal owner IDs, and managed-identity service principals.
- Azure action `Microsoft.Authorization/roleAssignments/read` reads subscription
  RBAC assignments for managed-identity correlation.

The scanner never requests application write permissions. Remediation commands
run separately under an operator identity and require explicit confirmation where
an automated change is safe.

## Data minimization

Findings do not contain tokens, credential values, credential key identifiers,
credential hints, complete redirect URIs, or owner personal details. Findings use
counts and boolean configuration states sufficient for triage.

## Reliability

Graph inventories follow `@odata.nextLink` and are cached for the scan lifetime.
Graph or Azure RBAC failures return an indeterminate `None` state; rules skip
evaluation and log the unavailable inventory rather than claiming compliance.

## Assignment restrictions

Resource-provider assignment restrictions for user-assigned managed identities
were intentionally deferred. Microsoft documents the portal feature, but the
current public Managed Identity REST response reliably exposes only
`isolationScope`. OpenShield will not infer a control from an undocumented field.

## References

- [App Registration security guidance](https://learn.microsoft.com/entra/identity-platform/security-best-practices-for-app-registration)
- [List applications](https://learn.microsoft.com/graph/api/application-list)
- [List application owners](https://learn.microsoft.com/graph/api/application-list-owners)
- [Service-principal property lock](https://learn.microsoft.com/graph/api/resources/serviceprincipallockconfiguration)
- [Managed Identity best practices](https://learn.microsoft.com/entra/identity/managed-identities-azure-resources/managed-identity-best-practice-recommendations)
