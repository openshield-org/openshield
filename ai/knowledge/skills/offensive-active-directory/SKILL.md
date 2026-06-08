---
name: offensive-active-directory
description: "Offensive methodology for Hybrid Active Directory and Entra ID (Azure AD). Covers pivots from on-premises to cloud (AAD Connect, Golden SAML) and cloud-to-on-prem (DCSync)."
domain: cybersecurity
subdomain: identity-access-management
tags:
- offensive
- active-directory
- hybrid-identity
- azure
- entra-id
- adfs
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.AC-1
- PR.AC-4
- PR.AC-7
- PR.AA-1
- PR.AA-2
---

# Hybrid Identity — Offensive Testing Methodology

## When to Use
- When performing red team assessments of Azure environments linked to on-premises AD.
- When validating the security of AAD Connect servers and federation infrastructure (AD FS).
- When investigating identity-based lateral movement from on-prem to cloud.
- When assessing the impact of on-premises compromise on Azure resources.

## Key Concepts

| Term | Definition |
|------|------------|
| AAD Connect | Tool used to sync on-premises AD objects to Azure Entra ID |
| Golden SAML | Attack where a stolen token-signing certificate is used to forge SAML assertions |
| DCSync | Technique used to replicate password hashes from a Domain Controller |
| Pass-the-PRT | Using a stolen Primary Refresh Token to hijack an Azure session |

## Offensive Pivot Points

### 1. AAD Connect Server
The AAD Connect server stores credentials for the `MSOL_` account, which can be abused for DCSync.

### 2. ADFS Golden SAML
Compromising the ADFS server allows for the extraction of the private key used for token signing, enabling unlimited session forgery.

### 3. Primary Refresh Token (PRT)
The PRT is the "gold" token in Entra ID. Stealing it from a joined device allows for session hijacking that bypasses MFA.

## Remediation Reference
- **Harden AAD Connect**: Restrict physical and network access to the AAD Connect server.
- **Use Phishing-Resistant MFA**: Deploy FIDO2 or Certificate-Based Auth to mitigate session theft.
- **Monitor for DCSync**: Use Microsoft Defender for Identity (MDI) to detect unusual replication requests.
