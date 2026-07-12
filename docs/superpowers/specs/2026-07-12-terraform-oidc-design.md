# Infrastructure as Code: Terraform for Render/Vercel + GitHub OIDC for Azure — Design

## Context

Issue #160. Two problems today:

1. All hosting (Render services, Vercel projects, Postgres) is click-ops — nothing about the live
   infrastructure is reviewable or reproducible from the repo.
2. CI's smoke-test workflow (`deploy.yml`) authenticates to Azure with a long-lived
   `AZURE_CLIENT_SECRET` GitHub secret. Rotating it is manual, and a forgotten rotation is invisible
   until something breaks or leaks.

Issue #160 explicitly depends on #157 (INFRA 4 — deterministic deploys, staging environment, worker
as its own Render service), which is not merged yet (open PR #172). The user has confirmed: model
the *current* live topology now, and treat the topology change as a real follow-up once #157 lands
— not something to block on today.

There is no Render, Vercel, or Azure API access available while writing this. The user confirmed:
ship this with every credential-shaped value as an empty/unset Terraform variable, with a
`terraform.tfvars.example` documenting what goes where. No `terraform apply` happens as part of this
work — this PR delivers reviewable code and docs, not a live-applied state.

## Current live topology (from `docs/api-render-deploy.md`, `docs/azure-setup.md`, `.env.example`,
`docker-compose.yml`, `Dockerfile`)

- **Render web service** `openshield-api` — Docker runtime (repo `Dockerfile`), start command
  `./startup.sh` (runs `alembic upgrade head`, backgrounds the worker as a subshell, execs gunicorn).
  Env vars: `DATABASE_URL`, `JWT_SECRET`, `ALLOWED_ORIGINS`, `AZURE_SUBSCRIPTION_ID`,
  `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`, `AZURE_TENANT_ID`, plus `ANTHROPIC_API_KEY`,
  `GROQ_API_KEY`, `GEMINI_API_KEY`, `NVD_API_KEY`, `SENTRY_DSN` per `.env.example`.
- **Render Postgres** `openshield-db` — free tier per docs (a Terraform variable, not hardcoded, since
  the live plan tier isn't confirmed).
- **Vercel project** `frontend/` — the React security dashboard, Vite framework preset, has its own
  `vercel.json` (rewrites + security headers).
- **Vercel project** `website/` — static HTML/Tailwind CDN site, has its own `vercel.json`.
- **Azure service principal** `openshield-scanner` — Reader role at subscription scope, currently
  client-secret auth. Used in two *distinct* contexts that must not be conflated:
  1. The product feature itself — end users configure their own Azure credentials to scan their own
     subscriptions. OIDC federation cannot apply here; it's inherent to GitHub Actions workflows, not
     an arbitrary SaaS customer's credential flow. Out of scope for this issue.
  2. The maintainer's own test subscription used by `deploy.yml`'s smoke-test job to run one real
     scan against real Azure resources as a deploy verification step. **This is the one OIDC applies
     to.**

`scanner/azure_client.py` calls `DefaultAzureCredential()` with no explicit credential type. Verified:
`DefaultAzureCredential`'s chain includes `WorkloadIdentityCredential`, which activates automatically
when `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_FEDERATED_TOKEN_FILE` are present in the
environment — exactly what `azure/login@v2` sets up when configured for OIDC (no `client-secret`
input). **No application code changes are needed** for the OIDC switch; it's entirely a workflow +
Azure AD configuration change.

## Known overlap to flag, not silently resolve

PR #172 (open, in progress, another contributor's #157 work) is *also* adding its own `render.yaml`
blueprint. Once #172 merges, there will be two infra-as-code approaches for the same Render services
(Terraform here, `render.yaml` blueprint there) that need reconciling — likely by removing the
blueprint in favor of Terraform, or vice versa. This design does not resolve that; it calls it out
explicitly in the PR description as a known follow-up, per the user's decision to write for current
topology now rather than wait.

## Design

### 1. `infra/terraform/`

```
infra/terraform/
  main.tf              # provider blocks (render-oss/render, vercel/vercel), Terraform Cloud `cloud {}` block
  variables.tf          # every credential-shaped value as a variable, no defaults for secrets
  render.tf             # render_postgresql.db, render_web_service.api
  vercel.tf              # vercel_project.dashboard, vercel_project.website
  outputs.tf            # service URLs, non-sensitive IDs
  terraform.tfvars.example   # documents every variable a real apply would need, no real values
  README.md             # plan/apply flow, how to point at a real Terraform Cloud workspace
```

- **State backend:** `cloud { organization = var placeholder, workspaces { name = "openshield" } }`
  documented as needing a real Terraform Cloud org (free tier) before `terraform init` will succeed
  against remote state. This matches the issue's own suggested option and avoids standing up new
  self-hosted backend infra (a bucket, etc.) as an unrelated side effect of this PR.
- **Render resources:** `render_postgres` for `openshield-db` (plan tier as a variable, default
  `"free"` documented as *probably* wrong — flagged in the tfvars example as "confirm against the
  live dashboard"). `render_web_service` for `openshield-api`: Docker runtime pointed at the repo,
  start command `./startup.sh`, env var block mixing plain values (`ALLOWED_ORIGINS`) and
  `sensitive = true` Terraform variables for secrets (`JWT_SECRET`, `AZURE_CLIENT_SECRET`-shaped
  slots are **not** included here — see below), matching the "current topology" from
  `docs/api-render-deploy.md`.
- **Vercel resources:** two `vercel_project` resources for `frontend` and `website`, each pointing at
  this repo with the correct root directory and framework preset (Vite for `frontend`, "other" /
  static for `website`), matching each directory's existing `vercel.json`.
- **All secret-shaped variables** (`render_api_key`, `vercel_api_token`, `jwt_secret`,
  `anthropic_api_key`, etc.) declared with `sensitive = true` and no default — Terraform will refuse
  to plan/apply without them being supplied via `terraform.tfvars` (gitignored) or CI secrets. The
  committed `terraform.tfvars.example` lists every variable name with a placeholder/comment, never a
  real value.

### 2. `terraform-plan.yml` GitHub Actions workflow

Triggers on PRs touching `infra/terraform/**`. Runs `terraform fmt -check`, `terraform init`,
`terraform validate`, and — only if `TF_API_TOKEN` is configured as a repo secret —
`terraform plan`, posting the plan output as a PR comment. If `TF_API_TOKEN` is absent (true today),
the plan step is skipped with a clear message rather than failing the workflow, mirroring the
existing community-friendly pattern in `deploy.yml` (fork/contributor CI must still pass green).

### 3. GitHub OIDC for the Azure smoke test

- `deploy.yml`: add `permissions: { id-token: write, contents: read }` to the job. Replace the
  smoke-test step's Azure env vars (`AZURE_CLIENT_SECRET` removed) with a preceding
  `azure/login@v2` step using `client-id: ${{ secrets.AZURE_CLIENT_ID }}`,
  `tenant-id: ${{ secrets.AZURE_TENANT_ID }}`, `subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}`
  — no `client-secret` input, which makes the action mint a federated OIDC token instead.
- New doc section (extends `docs/azure-setup.md` or a new `docs/ci-oidc-setup.md`) with the exact
  one-time Azure CLI commands the user must run against the *existing* `openshield-scanner` service
  principal: `az ad app federated-credential create` scoped to this repo + the `dev`/`main` branches
  (and optionally `pull_request` if the workflow ever runs on PRs), trusting
  `https://token.actions.githubusercontent.com`. I cannot run these — no Azure access — so this is
  documentation, not applied infrastructure.
- Update `docs/api-render-deploy.md`'s GitHub Secrets table: remove `AZURE_CLIENT_SECRET` from the
  required-for-real-scan-tests row.
- **Deleting the actual `AZURE_CLIENT_SECRET` GitHub secret is a manual, user-performed step** —
  irreversible-ish (if OIDC isn't actually working yet, deleting it breaks the smoke test), and
  requires repo admin access I don't have. The design documents this as the last step, done only
  after the user confirms `azure/login@v2` succeeds in a real run.

### 4. `docs/secrets-inventory.md`

A table cataloging every credential-shaped value in the project and where it lives:
GitHub Actions secret vs Render environment variable vs Terraform variable — including which ones
are redundant across two places today (e.g., `JWT_SECRET` must match between Render and GitHub) and
which move under Terraform management vs stay purely operational (rotated secrets never touch git).

## Testing

No live infrastructure to test against. Verification is:
- `terraform fmt -check` and `terraform validate` (works offline once providers are downloaded via
  `terraform init` — these don't call Render/Vercel/Azure APIs).
- `terraform-plan.yml` workflow itself must pass in CI on the PR (fmt/init/validate steps, with the
  actual `plan` step gracefully skipped since `TF_API_TOKEN` isn't configured).
- Existing test suite / ruff / other CI checks must stay green — this change touches no Python
  application code.

## Explicit non-goals for this PR

- Not implementing #157's topology (staging environment, worker as separate Render service) —
  tracked as a follow-up once #172 merges.
- Not reconciling the `render.yaml` blueprint vs Terraform overlap — flagged in the PR description.
- Not applying any Terraform (`terraform apply`) — no credentials available.
- Not deleting the `AZURE_CLIENT_SECRET` GitHub secret — manual, user-performed, after OIDC is
  confirmed working.
- Not changing how the deployed *product* authenticates to end-user Azure subscriptions — OIDC only
  applies to GitHub Actions' own authentication in `deploy.yml`.
