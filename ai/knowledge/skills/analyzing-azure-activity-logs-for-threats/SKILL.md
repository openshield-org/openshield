---
name: analyzing-azure-activity-logs-for-threats
description: Queries Azure Monitor activity logs and sign-in logs to detect suspicious administrative operations, impossible travel, and privilege escalation.
domain: cybersecurity
subdomain: security-operations
tags:
- azure
- monitoring
- kql
- threat-hunting
- activity-logs
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- DE.CM-1
- DE.CM-3
- DE.CM-7
- DE.AE-3
- RS.AN-1
---

# Analyzing Azure Activity Logs for Threats

## When to Use
- When investigating suspicious administrative activity in an Azure subscription.
- When performing a post-incident forensic analysis of a compromised tenant.
- When building custom KQL analytics rules for Microsoft Sentinel.
- When hunting for signs of privilege escalation or persistence.

## Key Concepts

| Term | Definition |
|------|------------|
| AzureActivity | Log table containing all administrative (write/delete) operations in Azure |
| SigninLogs | Log table containing all user and service principal authentication events |
| KQL | Kusto Query Language, used to query Azure Monitor and Sentinel data |
| Resource Provider | The Azure service (e.g., Microsoft.Compute) that performed the logged action |

## OpenShield Visibility Rules

OpenShield helps ensure you have the visibility required for these queries:
- **Logging**: `AZ-STOR-004` (Diagnostic Logs), `AZ-IDN-009` (Assignment Alerts)
- **Identity**: `AZ-IDN-007` (MFA Status), `AZ-IDN-002` (Conditional Access)

## Hunting Queries (KQL)

### 1. Detect Suspicious Role Assignments
```kql
AzureActivity
| where OperationNameValue == "Microsoft.Authorization/roleAssignments/write"
| where ActivityStatusValue == "Succeeded"
| extend Role = tostring(parse_json(Properties).roleDefinitionId)
```

### 2. Detect Cross-Tenant Data Access
```kql
StorageBlobLogs
| where OperationName == "GetBlob"
| where CallerIpAddress !in ("List_of_Trusted_IPs")
```

### 3. Detect Key Vault Secret Access
```kql
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where OperationName in ("SecretGet", "KeyGet")
```

## Remediation Reference
- **Centralize Logs**: Send all subscription logs to a central Log Analytics workspace.
- **Set Alerts**: Create analytics rules in Sentinel based on these queries for real-time alerting.
- **Harden RBAC**: Limit who can perform the `Microsoft.Authorization/roleAssignments/write` operation.
