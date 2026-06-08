---
name: building-identity-federation-with-saml-azure-ad
description: Establish SAML 2.0 identity federation between on-premises Active Directory and Microsoft Entra ID (Azure AD) for seamless cross-domain authentication and SSO.
domain: cybersecurity
subdomain: identity-access-management
tags:
- saml
- azure-ad
- entra-id
- federation
- hybrid-identity
- sso
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.AC-1
- PR.AC-4
- PR.AC-7
- DE.CM-3
- PR.AA-1
- PR.AA-2
---

# Building Identity Federation with SAML — Azure Focused

## When to Use
- When configuring hybrid identity for an Azure tenant linked to on-premises AD.
- When establishing SSO for enterprise applications via Microsoft Entra ID.
- When validating the security of SAML token-signing and federation trust.
- When investigating federation-based attack vectors like Golden SAML.

## Key Concepts

| Term | Definition |
|------|------------|
| IdP | Identity Provider (e.g., AD FS, Okta, Microsoft Entra ID) |
| SAML 2.0 | XML-based standard for exchanging authentication and authorization data |
| Token-Signing | Use of X.509 certificates to sign SAML assertions to ensure authenticity |
| Relying Party | The application or service that trusts the IdP for authentication |

## OpenShield Identity Rules

| Rule | Description | Severity |
|------|-------------|----------|
| AZ-IDN-009 | Missing Alerts for Role Assignment Changes | MEDIUM |
| AZ-IDN-002 | No MFA Enforced on Admin Accounts via Conditional Access | HIGH |
| AZ-IDN-004 | No Privileged Identity Management for Admin Roles | HIGH |

## Implementation Workflow

### Step 1: Prepare AD FS or IdP
Ensure the token-signing certificate is valid and not nearing expiry.

### Step 2: Configure Federated Domain in Entra ID
```powershell
# Using MS Graph to set federation
New-MgDomainFederationConfiguration -DomainId "corp.example.com" -BodyParameter $federationConfig
```

### Step 3: Configure Claim Rules
Map AD attributes (UPN, Email) to SAML assertions expected by Entra ID.

## Remediation Reference
- **Use Managed Auth**: Prefer Password Hash Sync (PHS) or Pass-Through Auth (PTA) over federation to reduce on-prem attack surface.
- **Rotate Certificates**: Implement a policy for regular rotation of token-signing certificates.
- **Monitor Federation Changes**: Set up alerts for changes to federation metadata or trusted domains.
