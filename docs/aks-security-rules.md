# AKS Security Rules

OpenShield evaluates Azure Kubernetes Service control-plane configuration through
the Azure Resource Manager API. The scanner does not download kubeconfig files,
request Kubernetes administrator credentials, or inspect in-cluster workloads.

## Coverage

| Rule | Control |
|---|---|
| `AZ-AKS-001` | Private API server endpoint |
| `AZ-AKS-002` | Local account disablement |
| `AZ-AKS-003` | Control-plane managed identity |
| `AZ-AKS-004` | OIDC issuer and Workload Identity |
| `AZ-AKS-005` | Azure Policy add-on |
| `AZ-AKS-006` | Managed node OS security upgrades |

## Required permissions

The scanning identity needs the following Azure Resource Manager action at the
subscription or relevant resource-group scope:

```text
Microsoft.ContainerService/managedClusters/read
```

Azure's built-in **Reader** role includes this action. No Kubernetes RBAC role,
cluster credential, Microsoft Graph permission, or data-plane access is needed.

If Azure denies or fails the inventory request, the AKS accessor returns an
indeterminate state. Rules skip evaluation and log the failure instead of
reporting the subscription as compliant.

## Remediation safety

The matching CLI playbooks validate the selected Azure account and cluster,
describe operational impact, and require the operator to type `APPLY`. Enabling
a private endpoint, disabling local credentials, migrating identity, or changing
node patch behavior should first be tested in a non-production cluster.

## Compliance note

This repository currently models CIS Microsoft Azure Foundations Benchmark
2.0.0. That benchmark does not directly identify these six AKS configuration
checks, so their CIS values are explicitly recorded as `N/A-AKS-*`. The rules
do not claim CIS Kubernetes Benchmark coverage. NIST CSF 1.1, ISO/IEC 27001:2013,
and SOC 2 mappings follow the framework versions already used by OpenShield.

## Authoritative references

- [Azure Policy built-ins for AKS](https://learn.microsoft.com/azure/aks/policy-reference)
- [AKS baseline architecture](https://learn.microsoft.com/azure/architecture/reference-architectures/containers/aks/baseline-aks)
- [AKS managed-cluster API](https://learn.microsoft.com/rest/api/aks/managed-clusters/get)
- [AKS node OS automatic upgrades](https://learn.microsoft.com/azure/aks/auto-upgrade-node-os-image)
