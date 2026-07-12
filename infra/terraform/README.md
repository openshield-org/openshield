# infra/terraform

Terraform for OpenShield's Render and Vercel infrastructure.

## Scope

Models the *current* live topology only: one Render web service (`openshield-api`), one Render
Postgres instance (`openshield-db`), and two Vercel projects (`frontend` dashboard, `website`
docs site). It does **not** yet model the staging environment or the worker-as-separate-service
split from issue #157 — that lands as a follow-up once [PR #172](https://github.com/openshield-org/openshield/pull/172)
merges. It also does not resolve the overlap with the `render.yaml` blueprint that PR #172
introduces; expect a reconciliation pass once that work lands (likely: pick one of Terraform or
the blueprint as the source of truth, not both).

## One-time setup (not done yet — no credentials exist in this repo)

1. Create a free [Terraform Cloud](https://app.terraform.io) organization and a workspace named
   `openshield`.
2. Replace `REPLACE_WITH_TFC_ORG` in `versions.tf` with your real organization name.
3. Run `terraform login` locally, or set `TF_API_TOKEN` in CI.
4. Copy `terraform.tfvars.example` to `terraform.tfvars` and fill in real values — **never commit
   this file** (it's gitignored).
5. Confirm the plan tier variables (`render_postgres_plan`, `render_web_service_plan`) against the
   real Render dashboard before the first apply — the defaults in `variables.tf` are documented
   best-guesses from `docs/api-render-deploy.md`, not verified against live infrastructure.
6. Since these resources (the `openshield-api` web service, `openshield-db` postgres instance, and
   both Vercel projects) already exist and were created via each dashboard's UI, the first
   `terraform apply` must be preceded by `terraform import` for each resource, or Terraform will try
   to create duplicates. See each provider's docs for the exact `terraform import` resource address
   and ID format.

## Plan/apply flow

- `terraform fmt -check` and `terraform validate` run automatically on every PR touching
  `infra/terraform/**` via `.github/workflows/terraform-plan.yml`.
- `terraform plan` also runs and is posted as a PR comment, but only once `TF_API_TOKEN` is
  configured as a repository secret — until then that step is skipped with a clear message, and the
  workflow still passes.
- Applies are manual (`terraform apply` from a local checkout with `terraform.tfvars` populated) until
  a dedicated apply-on-merge workflow is set up — not part of this issue's scope.
