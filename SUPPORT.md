# Support and Version Policy

## Supported releases

OpenShield supports the latest published minor release. Security fixes may also
be issued for the immediately preceding minor release when an upgrade cannot be
completed promptly. Older releases are unsupported unless a GitHub Security
Advisory explicitly states otherwise.

The authoritative release list is the project's GitHub Releases page. Users
should include the release tag or commit SHA when reporting a defect.

## Upgrading

1. Read `CHANGELOG.md` and the target GitHub Release notes.
2. Back up the database and deployment configuration.
3. Install the target source and its pinned dependency manifests.
4. Run `alembic upgrade head` before starting the API.
5. Validate `/health`, authentication, scanning and dashboard connectivity in a
   non-production environment before promotion.

Database-specific migration instructions are in
`docs/database-migrations.md`. Breaking changes and required operator actions
must be identified in release notes.

## Security support

Do not report vulnerabilities through a public issue. Follow
`.github/SECURITY.md` for the private reporting and coordinated disclosure
process.
