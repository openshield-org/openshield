# Secrets Inventory

Every credential-shaped value in this project, and exactly where it lives. Three categories:
GitHub Actions secrets, Render environment variables, and Terraform variables. A value can
legitimately live in more than one place (e.g. `JWT_SECRET` must match between Render and any
GitHub secret that signs tokens for smoke tests) — that overlap is called out explicitly below,
not treated as a bug.

## GitHub Actions secrets

| Secret | Used by | Purpose |
|---|---|---|
| `JWT_SECRET` | `deploy.yml` smoke tests | Must match the value configured on the Render web service; signs test JWTs |
| `API_URL` | `deploy.yml` (optional) | Overrides the default production API URL for smoke tests |
| `AZURE_SUBSCRIPTION_ID` | `deploy.yml` real-scan tests | Target subscription for the maintainer's own smoke-test scan |
| `AZURE_CLIENT_ID` | `deploy.yml` real-scan tests, `azure/login@v3` | Service principal client ID (OIDC, no secret needed as of #160) |
| `AZURE_TENANT_ID` | `deploy.yml` real-scan tests, `azure/login@v3` | Azure AD tenant ID (OIDC) |
| ~~`AZURE_CLIENT_SECRET`~~ | — | Removed by #160; see `docs/ci-oidc-setup.md` for the OIDC replacement and the manual deletion step |
| `TF_API_TOKEN` | `terraform-plan.yml` (once configured) | Terraform Cloud API token for `terraform plan` on infra PRs |

## Render environment variables (managed via Terraform going forward — `infra/terraform/render.tf`)

| Variable | Source in Terraform | Notes |
|---|---|---|
| `DATABASE_URL` | `var.database_url` | Points at the `render_postgres.db` instance's connection string |
| `JWT_SECRET` | `var.jwt_secret` (via `render_env_group.api_secrets`) | Must match the `JWT_SECRET` GitHub secret used for smoke tests |
| `ALLOWED_ORIGINS` | `var.allowed_origins` | CORS allowlist — the two Vercel project URLs |
| `ANTHROPIC_API_KEY` / `GROQ_API_KEY` / `GEMINI_API_KEY` | matching `var.*_api_key` | AI insights providers, at least one required |
| `NVD_API_KEY` | `var.nvd_api_key` | Optional, raises NVD rate limit |
| `SENTRY_DSN` | `var.sentry_dsn` | Optional error tracking |
| `AZURE_SUBSCRIPTION_ID` / `AZURE_CLIENT_ID` / `AZURE_TENANT_ID` | matching `var.azure_*` | For the maintainer's own smoke-test identity only — **not** end-user scan credentials |
| `AZURE_CLIENT_SECRET` | *(not in Terraform)* | Configured directly in the Render dashboard if the product itself still needs a standing credential for its own scheduled scans — operationally distinct from the CI smoke-test identity above, and out of scope for OIDC (OIDC only works for GitHub Actions workflows) |

## Terraform variables (`infra/terraform/variables.tf`)

Every variable above that flows into a Render or Vercel resource is declared `sensitive = true` with
no default, supplied via a local `terraform.tfvars` (gitignored) or CI secrets — see
`infra/terraform/terraform.tfvars.example` for the full list and `infra/terraform/README.md` for the
plan/apply flow.
