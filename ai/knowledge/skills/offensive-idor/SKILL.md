---
name: offensive-idor
description: "Insecure Direct Object Reference (IDOR) testing skill focused on Azure resource identifiers and API endpoints. Covers GUID enumeration, horizontal/vertical privilege escalation, and Azure-specific object reference vulnerabilities."
domain: cybersecurity
subdomain: web-security
tags:
- idor
- azure
- api-security
- guidance
- web-security
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.AC-4
- PR.AC-7
- PR.DS-1
- DE.CM-1
---

# Insecure Direct Object References (IDOR) — Azure Offensive Methodology

## When to Use
- When testing Azure-hosted web applications and APIs that use resource identifiers (IDs, GUIDs) in requests.
- When validating if users can access or modify resources belonging to other tenants or users.
- When assessing the security of Azure Storage pre-signed URLs (SAS tokens) as object references.
- When performing security audits of internal administrative portals that manage Azure resources.

## Key Concepts

| Term | Definition |
|------|------------|
| Horizontal Escalation | Accessing resources of another user with the same privilege level |
| Vertical Escalation | Accessing resources that require a higher privilege level (e.g., admin) |
| BOLA | Broken Object Level Authorization, the API-specific term for IDOR |
| SAS Token | Azure Storage Shared Access Signature, often used as a direct object reference |

## Detection & Exploitation

### API IDOR Discovery
Many Azure-integrated apps use GUIDs. While GUIDs are not sequential, they may be leaked in other API responses.

```bash
# Example: Accessing a profile by ID
GET /api/v1/users/a1b2c3d4-e5f6-7890-abcd-ef1234567890/settings

# Test: Replace with a victim's GUID found in a search or list endpoint
GET /api/v1/users/<victim-guid>/settings
```

### Azure Storage SAS Token Manipulation
SAS tokens are often used to grant temporary access to blobs. If the token is not scoped correctly or has a long expiry, it acts as a vulnerable object reference.

```bash
# Test for scope: Can I access another blob in the same container?
https://mystorage.blob.core.windows.net/mycontainer/secret.txt?<sas-token>
# Change to:
https://mystorage.blob.core.windows.net/mycontainer/other_user_file.txt?<sas-token>
```

## Remediation Reference
- **Check Ownership**: Always verify on the server side that the authenticated user owns the object they are requesting.
- **Use UUIDs**: While not a replacement for auth, using non-sequential UUIDs prevents basic enumeration.
- **Scope SAS Tokens**: Always use the most restrictive permissions and shortest possible expiry for SAS tokens.
