---
name: analyzing-cloud-storage-access-patterns
description: Detect abnormal access patterns in Azure Blob Storage by analyzing Storage Analytics and diagnostic logs. Identifies after-hours bulk downloads, access from new IP addresses, unusual API calls (GetBlob spikes), and potential data exfiltration.
domain: cybersecurity
subdomain: cloud-security
tags:
- storage
- azure-blob
- access-patterns
- threat-hunting
- cloud-security
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.DS-1
- PR.DS-2
- PR.DS-3
- PR.AC-3
- DE.CM-1
- DE.CM-7
- PR.IP-4
---

# Analyzing Cloud Storage Access Patterns — Azure Focused

## When to Use
- When investigating potential data exfiltration from Azure Storage Accounts.
- When building KQL hunting queries for Storage account activity.
- When validating if access to sensitive blobs follows established baselines.
- When performing security audits of Storage SAS token usage and public access.

## Key Concepts

| Term | Definition |
|------|------------|
| Storage Analytics | Azure feature that provides logs and metrics for storage accounts |
| Diagnostic Settings | Configuration to send storage logs to Log Analytics or Event Hub |
| SAS Token | Shared Access Signature, providing temporary delegated access to storage |
| Data Exfiltration | Unauthorized transfer of data from a storage account to an external system |

## OpenShield Storage Rules

| Rule | Description | Severity |
|------|-------------|----------|
| AZ-STOR-001 | Public Blob Access Enabled on Storage Account | HIGH |
| AZ-STOR-004 | Storage Account Diagnostic Logging Disabled | MEDIUM |
| AZ-STOR-002 | Storage Account Allows HTTP Traffic | MEDIUM |
| AZ-STOR-003 | Storage Account Has No Lifecycle Management Policy | LOW |

## Analysis Workflow

### Step 1: Enable and Query Diagnostic Logs
Ensure logs are sent to Log Analytics and use KQL to identify spikes.

```kql
// Identify bulk GetBlob operations from a single IP
StorageBlobLogs
| where OperationName == "GetBlob"
| summarize RequestCount = count() by CallerIpAddress, bin(TimeGenerated, 1h)
| where RequestCount > 100
```

### Step 2: Build Access Baselines
Monitor for access from new source IPs or unusual hours.

### Step 3: Detect Anomalies
- **Spikes**: Sudden increase in `GetBlob` or `ListBlobs` calls.
- **Geography**: Access from IPs in countries where the organization does not operate.
- **Success/Failure Ratio**: High number of `403 Forbidden` errors indicating enumeration.

## Remediation Reference
- **Disable Public Access**: Use `az storage account update --allow-blob-public-access false`.
- **Enforce HTTPS**: Use `az storage account update --https-only true`.
- **Use Private Endpoints**: Restrict storage access to internal VNet traffic only.
