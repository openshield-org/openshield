---
name: offensive-cloud
description: "Azure-specific offensive security testing methodology. Covers credential harvesting (IMDS, managed identities), enumeration, privilege escalation, and data exfiltration within Azure subscriptions and Entra ID tenants."
domain: cybersecurity
subdomain: cloud-security
tags:
- offensive
- azure
- entra-id
- imds
- privilege-escalation
- data-exfiltration
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.AC-1
- PR.AC-3
- PR.AC-4
- PR.AC-7
- PR.DS-1
- PR.DS-2
- DE.CM-1
---

# Azure — Offensive Testing Methodology

## When to Use
- When performing cloud penetration testing on Azure infrastructure.
- When validating the blast radius of a compromised Azure identity (user or service principal).
- When assessing the security of Azure resources like Key Vault, Storage Accounts, and Virtual Machines.
- When investigating paths for privilege escalation within an Azure subscription.

## Key Concepts

| Term | Definition |
|------|------------|
| IMDS | Instance Metadata Service, provides identity tokens to Azure VMs |
| Managed Identity | An identity for Azure resources, eliminating the need for hardcoded credentials |
| RBAC | Role-Based Access Control, determines what actions an identity can perform |
| ROADtools | A popular toolkit for Azure Entra ID enumeration and analysis |

## Offensive Workflow

### Step 1: Identity Discovery
Identify the current context using `az account show` and `az ad signed-in-user show`.

### Step 2: Privilege Escalation
Search for "Owner" or "User Access Administrator" roles that allow self-elevation.

### Step 3: Data Exfiltration
Extract secrets from Key Vault or keys from Storage Accounts:
```bash
az keyvault secret list --vault-name <vault>
az storage account keys list -n <account>
```

## Remediation Reference
- **Use Managed Identities**: Avoid using service principal secrets; use System-Assigned or User-Assigned Managed Identities.
- **Enforce Least Privilege**: Use custom RBAC roles with specific permissions instead of broad roles like "Contributor".
- **Harden Key Vault**: Enable firewall and "Purge Protection" on all Key Vaults.
