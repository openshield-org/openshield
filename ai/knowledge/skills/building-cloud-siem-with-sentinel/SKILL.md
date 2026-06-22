---
name: building-cloud-siem-with-sentinel
description: Deploy Microsoft Sentinel as a cloud-native SIEM and SOAR platform for Azure. Covers configuring data connectors (Entra ID, Azure Activity), writing KQL detection queries, and building automated response playbooks.
domain: cybersecurity
subdomain: security-operations
tags:
- microsoft-sentinel
- cloud-siem
- kql-queries
- soar-automation
- threat-detection
- azure
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

# Building Cloud SIEM with Sentinel — Azure Focused

## When to Use
- When establishing a centralized security operations center (SOC) for Azure.
- When building automated incident response workflows for Azure-specific threats.
- When performing threat hunting across Azure security telemetry using KQL.
- When integrating threat intelligence feeds with Azure Activity and Entra ID logs.

## Key Concepts

| Term | Definition |
|------|------------|
| KQL | Kusto Query Language, used for searching and analyzing data in Sentinel |
| Analytics Rule | Detection logic that creates incidents when specific conditions match |
| SOAR Playbook | Automated workflow triggered by incidents to perform response actions |
| Data Connector | Module that ingests security logs from Azure services into Sentinel |

## OpenShield Monitoring Rules

OpenShield identifies gaps in the logging required for an effective SIEM:
- **Logging**: `AZ-STOR-004` (Diagnostic Logs), `AZ-IDN-009` (Role Assignment Alerts)
- **Identity**: `AZ-IDN-007` (MFA Status), `AZ-IDN-002` (Conditional Access)

## SIEM Workflow

### Step 1: Provision Sentinel
Enable Microsoft Sentinel on a Log Analytics workspace.

### Step 2: Enable Connectors
Ingest Entra ID Sign-in/Audit logs and Azure Activity logs.

### Step 3: Write Detection Queries
Example: Detect impossible travel or mass resource deletions.

### Step 4: Automate Response
Use Logic Apps to automatically disable compromised Entra ID accounts.

## Remediation Reference
- **Enable Diagnostic Settings**: Ensure all critical resources send logs to the Sentinel workspace.
- **Use Fusion Rules**: Enable Sentinel's multi-stage attack detection (Fusion) for high-fidelity alerts.
- **Automate Remediation**: Link OpenShield findings to Sentinel incidents for automated response.
