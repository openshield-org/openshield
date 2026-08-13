# Azure Enterprise Resilience Rules

OpenShield evaluates Azure Functions, Private Link, and Recovery Services vault
configuration through Azure Resource Manager. It does not read application
settings, connection strings, deployment credentials, private IP addresses,
backup items, recovery points, encryption keys, or customer data.

## Coverage

| Pack | Rules | Controls |
|---|---|---|
| Azure Functions | `AZ-FUNC-001`–`005` | HTTPS, TLS 1.2, FTP publishing, remote debugging, managed identity |
| Private Endpoint | `AZ-PE-001`–`006` | Storage, SQL, PostgreSQL, App Service, Recovery Services, connection approval |
| Azure Backup | `AZ-BAK-001`, `002`, `004`, `006` | Soft delete, immutability, MUA, Azure Monitor alerts |

Private Link checks evaluate public-network state and approved target groups
together. A private endpoint does not itself disable a service's public
endpoint. Storage currently requires the `blob` target group as the universal
minimum; additional service groups such as `file`, `queue`, `table`, `dfs`, and
`web` depend on which data services the account uses and are not inferred.

The Backup baseline requires soft delete to be `Enabled` or `AlwaysON` with at
least 35 days of retention. Immutability locking is deliberately not automated:
the locked state is irreversible. Storage redundancy and production-only lock
policies remain outside this first phase because they require organization
specific exceptions and production classification.

## Required permissions

Azure's built-in Reader role normally includes the required management-plane
read actions:

```text
Microsoft.Web/sites/read
Microsoft.Web/sites/config/read
Microsoft.Network/privateEndpoints/read
Microsoft.Storage/storageAccounts/read
Microsoft.Sql/servers/read
Microsoft.DBforPostgreSQL/flexibleServers/read
Microsoft.RecoveryServices/vaults/read
```

Each inventory has an explicit indeterminate state. If a required API fails or
a security property is absent, affected rules log and skip the resource instead
of creating a finding or claiming compliance.

## Remediation safety

Network isolation can interrupt applications, deployment systems, backup
agents, and administrators when private DNS or routing is incomplete. Validate
the resource, hosting tier, private endpoint approval, DNS, and client path
before disabling public access. Backup immutability must be reviewed separately
and is never locked by an OpenShield playbook.

## Compliance mappings

The repository's CIS Azure Foundations version has no direct controls for all
of these settings. Each rule therefore uses a unique `N/A-FUNC-*`, `N/A-PE-*`,
or `N/A-BAK-*` identifier to state explicitly that no direct CIS recommendation
is assigned. NIST, ISO 27001, and SOC 2 mappings use the framework versions
already represented by OpenShield.

## References

- [Azure Functions security](https://learn.microsoft.com/azure/azure-functions/security-concepts)
- [Azure Private Endpoint overview](https://learn.microsoft.com/azure/private-link/private-endpoint-overview)
- [Azure Storage private endpoints](https://learn.microsoft.com/azure/storage/common/storage-private-endpoints)
- [Azure Backup security best practices](https://learn.microsoft.com/azure/backup/azure-backup-data-protection-best-practices)
- [Azure Backup multiuser authorization](https://learn.microsoft.com/azure/backup/multi-user-authorization-concept)
