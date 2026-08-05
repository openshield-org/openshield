# Project Access Continuity

OpenShield's public component ownership is recorded in `.github/CODEOWNERS`.
OpenSSF continuity requires more than public names: organization owners must
verify that the project can continue if any one person becomes unavailable.

## Required capability matrix

At least two currently available people must independently be able to perform
each critical capability, or use a tested organization-controlled recovery
process:

| Capability | Primary confirmed | Backup confirmed | Last tested |
|---|---|---|---|
| Triage and close issues | Owner record | Owner record | Date required |
| Review and merge approved changes | Owner record | Owner record | Date required |
| Publish and verify a release | Owner record | Owner record | Date required |
| Recover GitHub organization access | Owner record | Owner record | Date required |
| Manage production deployment access | Owner record | Owner record | Date required |
| Manage domain/DNS access, if applicable | Owner record | Owner record | Date required |
| Rotate security-reporting access | Owner record | Owner record | Date required |

Names and recovery details may remain in a private owner-controlled record when
publishing them would increase risk. The public OpenSSF justification should
state the date of verification and that two independent holders were confirmed,
without exposing secrets.

## Review process

- Review the matrix at least every six months and before each major release.
- Remove access promptly when a role ends and confirm the backup remains valid.
- Test recovery without sharing credentials between individuals.
- Store recovery material outside any single maintainer's personal account.
- Record the review in issue #205 or another auditable owner-approved record.

The continuity and bus-factor criteria must remain pending until an organization
owner completes and records this verification. Documentation alone is not proof.
