# OpenShield Governance

OpenShield uses a maintainer-led, consensus-seeking governance model. Technical
discussion happens in public GitHub issues and pull requests. The maintainers
seek agreement through review; when consensus cannot be reached, the project
lead makes the final decision and records the reasoning publicly.

## Roles

- **Project lead:** sets project direction, appoints maintainers, manages
  releases and resolves decisions that cannot reach consensus.
- **Maintainers:** triage issues, review changes, uphold security and quality
  requirements, and merge approved pull requests in their assigned areas.
- **Security maintainers:** privately triage vulnerability reports, coordinate
  fixes and advisories, and ensure reporter credit is handled according to the
  security policy.
- **Contributors:** propose issues and changes, participate in review, add tests
  and documentation, and follow the Code of Conduct and contribution policy.

Current role holders and component responsibilities are listed in
[`MAINTAINERS.md`](MAINTAINERS.md). Repository paths also have review owners in
`.github/CODEOWNERS`.

## Decision and change process

1. Material changes begin with a GitHub issue describing the problem, scope and
   acceptance criteria.
2. Implementation is submitted by pull request to `dev` and must pass required
   automated checks.
3. At least one qualified reviewer must approve before merge. Authors do not
   approve their own changes.
4. Releases are promoted from `dev` to `main` and published by an authorized
   maintainer.
5. Security-sensitive decisions may be discussed privately until coordinated
   disclosure, after which the advisory and fix are made public.

## Appointing and removing maintainers

Regular contributors may be nominated as maintainers based on sustained,
constructive work and demonstrated knowledge of the relevant component. The
project lead confirms appointments after consulting existing maintainers.
Maintainers may step down at any time. Access may be removed for inactivity,
security risk, repeated policy violations, or Code of Conduct violations.

## Continuity

The project intends to maintain at least two people capable of issue triage,
pull-request review, merging and release operations. Administrative access,
deployment access, domains and recovery methods must be held through
organization-controlled accounts or recoverable records rather than a single
person's undocumented credentials.

The project lead reviews continuity access before each release. The names of
people who currently hold each capability are intentionally confirmed through
private organization records; `MAINTAINERS.md` lists the public accountable
roles without publishing secret locations or recovery details.

## Governance changes

Governance changes use the normal issue and pull-request process and require
approval from the project lead and one additional maintainer. Emergency
security changes may be merged first and documented immediately afterward.
