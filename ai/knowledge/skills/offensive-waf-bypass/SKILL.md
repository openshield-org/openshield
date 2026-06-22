---
name: offensive-waf-bypass
description: "WAF bypass techniques checklist for Azure Front Door and Application Gateway. Covers encoding bypass, header manipulation, and Azure-specific evasion strategies."
domain: cybersecurity
subdomain: web-security
tags:
- waf
- azure-front-door
- application-gateway
- evasion
- web-security
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.AC-3
- PR.AC-5
- SI-3
- PR.DS-1
- DE.CM-1
---

# WAF Bypass Techniques — Azure Focused

## When to Use
- When testing web applications protected by Azure Front Door WAF or Application Gateway WAF.
- When payloads are being blocked by default CRS (Common Rule Set) rules.
- When validating the effectiveness of custom WAF rules and rate limiting.
- When assessing if the backend origin can be reached directly, bypassing the WAF.

## Key Concepts

| Term | Definition |
|------|------------|
| CRS | Common Rule Set, the base rules used by Azure WAF (e.g., OWASP 3.2) |
| Front Door | Azure's global CDN and security layer with integrated WAF |
| App Gateway | Azure's regional load balancer with integrated WAF |
| Origin Bypass | Directly connecting to the backend IP/hostname to skip WAF inspection |

## Evasion Strategies for Azure WAF

### 1. Origin Bypass (Direct-to-IP)
If the backend application (App Service, VM) is not restricted to Front Door/App Gateway IPs, an attacker can bypass the WAF entirely.

```bash
# Test if origin is reachable directly
curl -v https://<backend-ip-or-dns>/api/test
```

### 2. Encoding and Obfuscation
Azure WAF (CRS) can sometimes be bypassed using specific encoding combinations that the WAF doesn't normalize but the backend does.
- **Double URL Encoding**: `UNION` → `%2555%254E%2549%254F%254E`
- **Case Variation**: `SeLeCt` instead of `SELECT`
- **Comment Injection**: `UN/**/ION SE/**/LECT`

### 3. Header Manipulation
Some WAF rules can be confused by malformed or duplicate headers.
- **Duplicate Headers**: `X-Forwarded-For: 1.2.3.4` followed by `X-Forwarded-For: 127.0.0.1`
- **Large Headers**: Sending headers larger than the WAF's buffer (e.g., > 8KB).

## Remediation Reference
- **Restrict Access to WAF IPs**: Ensure backend resources only accept traffic from Azure Front Door or App Gateway Service Tags.
- **Enforce WAF Prevention Mode**: Ensure WAF is in "Prevention" mode, not just "Detection".
- **Keep CRS Updated**: Regularly update to the latest CRS version (e.g., 3.2 or Managed Rulesets).
