# Database Migrations

OpenShield manages its PostgreSQL schema with Alembic. Application queries remain
raw SQL; migration files define schema operations explicitly and do not introduce
ORM models or SQLAlchemy metadata.

All commands below run from the repository root and require `DATABASE_URL` in the
environment:

```bash
export DATABASE_URL=postgresql://openshield:openshield@localhost:5432/openshield
```

## Fresh databases

Create the complete current schema by upgrading to the latest revision:

```bash
alembic upgrade head
alembic current
```

Production startup runs `alembic upgrade head` once, before starting the worker
and Gunicorn. The Flask application does not create or migrate tables.

## Deployment checklist

For a brand-new database:

1. Set `DATABASE_URL`.
2. Deploy normally; `startup.sh` runs `alembic upgrade head`.
3. Confirm `alembic current` reports the head revision.

For an existing production database that already has OpenShield tables:

1. Back up the database.
2. Verify the live schema matches the baseline revision in `alembic/versions/`.
3. Run `alembic stamp head` once before the first Alembic-enabled deployment.
4. Deploy normally; `startup.sh` must continue to run only `alembic upgrade head`.

Do not automate `alembic stamp head` in application code, startup scripts,
containers, or deployment configuration.

## Existing production databases

The baseline migration represents the schema that OpenShield already created in
production before Alembic was adopted. It must not be run against an unversioned
database that already contains the `scans` and `findings` tables.

Before deploying this Alembic-enabled release to an existing production database:

1. Back up the database.
2. Verify that `scans`, `findings`, their columns, constraints, and indexes match
   the baseline revision in `alembic/versions/`.
3. Record the existing schema at the baseline revision without executing DDL:

   ```bash
   alembic stamp head
   alembic current
   ```

This is a one-time operational step for existing databases. Never add automatic
stamping to application code, startup scripts, containers, or deployment
configuration. After stamping, normal deployments use only:

```bash
alembic upgrade head
```

## Creating a migration

Create an empty revision with a short, descriptive, imperative message:

```bash
alembic revision -m "add finding source"
```

Because OpenShield has no ORM metadata, do not use `--autogenerate`. Implement
both `upgrade()` and `downgrade()` explicitly with Alembic operations, then review
the generated file before applying it.

Migration files use Alembic's standard `<revision>_<slug>.py` naming. Keep the
message lowercase and specific to one schema change, for example
`add_scan_region` or `index_findings_detected_at`. Each revision must point to the
current head through `down_revision`; do not create parallel heads.

## Contributor workflow

1. Start PostgreSQL and export `DATABASE_URL`.
2. Update to the current schema with `alembic upgrade head`.
3. Create and implement the new revision.
4. Test the upgrade from the previous revision.
5. Test `alembic downgrade -1` and then `alembic upgrade head` on disposable data.
6. Test the full migration chain against a fresh empty database.
7. Run the application test suite.

Useful inspection commands:

```bash
alembic current
alembic history --verbose
alembic heads
alembic upgrade head --sql
```

Treat downgrades as destructive operations and run them only against a database
whose data can be restored.
