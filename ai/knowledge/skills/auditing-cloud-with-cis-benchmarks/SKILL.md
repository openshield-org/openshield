---
name: auditing-cloud-with-cis-benchmarks
description: Conduct cloud security audits using Center for Internet Security (CIS) benchmarks for Azure. Covers interpreting CIS Foundations Benchmark controls, running automated assessments, and maintaining continuous compliance monitoring.
domain: cybersecurity
subdomain: compliance
tags:
- cis-benchmarks
- compliance
- azure
- audit
- security-hardening
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- GV.SC-1
- PR.DS-1
- PR.AC-3
- PR.AC-4
- PR.AC-7
- DE.CM-1
- DE.CM-7
- PR.IP-12
---

# Auditing Cloud with CIS Benchmarks — Azure Focused

## When to Use
- When performing initial security audits of an Azure tenant against industry-standard benchmarks.
- When preparing for SOC 2 or ISO 27001 audits that reference CIS controls.
- When establishing a measurable security baseline for new Azure subscriptions.
- When validating the configuration of Identity, Networking, and Storage against best practices.

## Key Concepts

| Term | Definition |
|------|------------|
| CIS Benchmark | Prescriptive security configuration guidelines developed by the Center for Internet Security |
| Level 1 Profile | Practical security controls implementable without significant performance impact |
| Level 2 Profile | Defense-in-depth controls that may restrict functionality |
| Foundations Benchmark | CIS benchmark specifically for cloud providers covering IAM, Logging, and Networking |

## OpenShield Compliance Rules

OpenShield automates many of the CIS Azure Foundations Benchmark checks:
- **Identity**: `AZ-IDN-001` through `AZ-IDN-009`
- **Networking**: `AZ-NET-001` through `AZ-NET-014`
- **Storage**: `AZ-STOR-001` through `AZ-STOR-005`

## Audit Workflow

### Step 1: Run Automated Assessment
Use OpenShield or native Azure tools like Microsoft Defender for Cloud to run a full CIS scan.

### Step 2: Interpret Results
Prioritize Level 1 controls first as they represent fundamental security hygiene.

### Step 3: Remediate High Impact Controls
Address failed controls like unrestricted RDP/SSH access or missing MFA on admin accounts.

## Remediation Reference
- **Use Azure Policy**: Assign the "CIS Microsoft Azure Foundations Benchmark" policy initiative for continuous auditing.
- **Enable Defender**: Use Microsoft Defender for Cloud for real-time compliance tracking.
- **Automate Fixes**: Use OpenShield playbooks to automatically remediate common CIS failures.
