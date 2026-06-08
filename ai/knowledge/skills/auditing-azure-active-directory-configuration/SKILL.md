---
name: auditing-azure-active-directory-configuration
description: Auditing Microsoft Entra ID (Azure Active Directory) configuration to identify risky authentication policies, overly permissive role assignments, and guest user risks.
domain: cybersecurity
subdomain: cloud-security
tags:
- azure
- entra-id
- active-directory
- iam-audit
- conditional-access
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.AC-1
- PR.AC-4
- PR.AC-7
- DE.CM-3
- ID.AM-08
- DE.CM-01
- PR.IR-01
- GV.SC-06
---

# Auditing Microsoft Entra ID Configuration

## When to Use
- When performing a security assessment of an Azure tenant's identity configuration.
- When validating if Conditional Access policies adequately protect against identity-based attacks.
- When investigating suspicious sign-in activity or compromised accounts.
- When auditing privileged role assignments (Global Admins, etc.) for least privilege.

## Key Concepts

| Term | Definition |
|------|------------|
| Conditional Access | Policy engine used to enforce MFA and device compliance |
| Security Defaults | Microsoft's baseline security settings for all tenants |
| PIM | Privileged Identity Management, for just-in-time role elevation |
| Legacy Auth | Older protocols (IMAP/POP3) that do not support MFA |

## OpenShield Identity Rules

OpenShield automates these audit steps:
- **MFA**: `AZ-IDN-002` (Admin MFA), `AZ-IDN-007` (User MFA)
- **Roles**: `AZ-IDN-001` (SP Owner), `AZ-IDN-005` (Guest Admin)
- **Management**: `AZ-IDN-004` (Missing PIM), `AZ-IDN-009` (Assignment Alerts)

## Audit Workflow

### Step 1: Baseline Check
Check if Security Defaults are enabled or if Conditional Access is covering all users.

### Step 2: Privileged Roles Audit
List all Global Administrators and ensure they have PIM enabled and MFA enforced.

### Step 3: Guest User Review
Identify guest users with high-privilege directory or subscription roles.

## Remediation Reference
- **Block Legacy Auth**: Ensure Conditional Access policies explicitly block legacy authentication protocols.
- **Enable PIM**: Migrate permanent admin assignments to eligible PIM assignments.
- **Restrict App Consent**: Disable the ability for users to consent to apps requesting sensitive data.
