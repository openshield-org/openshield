---
name: building-identity-governance-lifecycle-process
description: Builds comprehensive identity governance and lifecycle management processes in Azure Entra ID, including JML (Joiner-Mover-Leaver) automation and periodic access reviews.
domain: cybersecurity
subdomain: identity-access-management
tags:
- identity-governance
- lifecycle-management
- jml
- access-provisioning
- azure
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

# Building Identity Governance & Lifecycle — Azure Focused

## When to Use
- When automating the onboarding and offboarding of users in an Azure tenant.
- When configuring Entra ID Governance features like access reviews and entitlement management.
- When establishing a "birthright" access model for new employees based on job code.
- When auditing orphaned accounts belonging to terminated users.

## Key Concepts

| Term | Definition |
|------|------------|
| JML | Joiner-Mover-Leaver, the core lifecycle of an employee identity |
| Birthright Access | Permissions automatically granted to every user in a specific group or department |
| Access Review | Periodic process where managers certify that their employees still need specific permissions |
| Orphaned Account | A valid account in a system that no longer corresponds to an active employee |

## OpenShield Identity Rules

| Rule | Description | Severity |
|------|-------------|----------|
| AZ-IDN-007 | Active User with No MFA Registered in Entra ID | HIGH |
| AZ-IDN-003 | Unrestricted Guest Invitations Allowed in Entra ID | MEDIUM |
| AZ-IDN-006 | Service Principal Secrets Not Rotated Recently | MEDIUM |

## Lifecycle Workflow

### Step 1: Define Joiner Process
Automate account creation via HR feed integration (e.g., Workday to Entra ID).

### Step 2: Implement Access Reviews
Configure quarterly reviews for high-privilege roles like Global Administrator.

### Step 3: Offboarding (Leaver)
Ensure accounts are disabled immediately upon HR status change.

## Remediation Reference
- **Use PIM**: Implement Privileged Identity Management for just-in-time elevation.
- **Automate Termination**: Use Entra ID Lifecycle Workflows to trigger access revocation.
- **Audit Guests**: Regularly review and remove guest users who haven't signed in for 90+ days.
