# Terraform IaC + Azure OIDC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Codify Render/Vercel infrastructure as Terraform (current live topology only) and switch the
Azure smoke-test workflow from a long-lived client secret to GitHub OIDC federation.

**Architecture:** A new `infra/terraform/` root with the `render-oss/render` and `vercel/vercel`
providers, state in Terraform Cloud (`cloud {}` block, org/workspace supplied by the user later — not
applied in this PR). A `terraform-plan.yml` workflow validates and (once `TF_API_TOKEN` exists)
plans on PRs touching `infra/terraform/**`. `deploy.yml`'s Azure smoke-test step switches to
`azure/login@v3` with OIDC; no application code changes since `DefaultAzureCredential()` already
picks up workload-identity federation automatically.

**Tech Stack:** Terraform >= 1.6 (for the `cloud` block), `render-oss/render` provider,
`vercel/vercel` provider (>= 4.8), `azure/login@v3` GitHub Action.

## Global Constraints

- No live Render/Vercel/Azure/Terraform Cloud credentials exist yet. Every credential-shaped
  Terraform variable is declared `sensitive = true` with **no default** — real values are supplied
  later via `terraform.tfvars` (gitignored) or CI secrets, never committed.
- No `terraform apply` happens in this work. Verification is `terraform fmt -check`,
  `terraform init` (downloads providers, no auth needed), and `terraform validate`.
- Model the *current* live topology only (from `docs/api-render-deploy.md`): one Render web service
  `openshield-api` (Docker runtime, `./startup.sh` start command), one Render Postgres
  `openshield-db`, two Vercel projects (`frontend` = dashboard, `website` = docs site). Do not add
  the staging environment or a separate worker service — that's #157/#172's job, done later.
- OIDC applies only to `deploy.yml`'s smoke-test Azure login, not to the product's own
  `DefaultAzureCredential()` usage for scanning end-user subscriptions (`scanner/azure_client.py` —
  do not touch this file).
- Deleting the `AZURE_CLIENT_SECRET` GitHub secret is a manual, user-performed step after they
  confirm OIDC works in a real run. Do not attempt it via `gh` or any tool.
- Verified resource schemas (fetched from the providers' own docs, not assumed):
  - `render_web_service`: required `name`, `plan`, `region`, `runtime_source` block. `runtime_source.docker`
    block requires `branch`, `repo_url`; optional `dockerfile_path`. Optional top-level: `env_vars`
    (map of `{ value = "..." }`), `start_command`.
  - `render_postgres`: required `name`, `plan`, `region`, `version`. Optional `database_name`,
    `database_user`.
  - `render_env_group`: required `name`. Optional `env_vars` (map of `{ value = "..." }` or
    `{ generate_value = true }`).
  - `render_env_group_link`: required `env_group_id`, `service_ids` (set).
  - Render provider block: `api_key`, `owner_id` (from `RENDER_API_KEY`, `RENDER_OWNER_ID` env vars).
  - `vercel_project`: required `name`. Optional `framework`, `root_directory`,
    `git_repository = { type = "github", repo = "..." }`, `environment` (set of
    `{ key, value, target, sensitive }`).
  - Vercel provider block: `api_token` (from `VERCEL_API_TOKEN` env var), optional `team`.
  - `azure/login@v3` OIDC inputs: `client-id`, `tenant-id`, `subscription-id` (no `client-secret`).
    Requires workflow-level `permissions: { id-token: write, contents: read }`.
  - Terraform Cloud remote state: `terraform { cloud { organization = "..." workspaces { name = "..." } } }`.

---

### Task 1: Terraform skeleton — providers, backend, core variables

**Files:**
- Create: `infra/terraform/versions.tf`
- Create: `infra/terraform/variables.tf`
- Create: `infra/terraform/terraform.tfvars.example`
- Create: `infra/terraform/.gitignore`

**Interfaces:**
- Produces: `var.render_api_key`, `var.render_owner_id`, `var.vercel_api_token`, `var.vercel_team`,
  `var.tfc_organization`, `var.tfc_workspace_name` — every later task's provider config and resource
  block consumes these.

- [ ] **Step 1: Create the backend + provider requirements file**

```hcl
# infra/terraform/versions.tf
terraform {
  required_version = ">= 1.6"

  cloud {
    organization = "REPLACE_WITH_TFC_ORG"
    workspaces {
      name = "openshield"
    }
  }

  required_providers {
    render = {
      source  = "render-oss/render"
      version = "~> 1.8"
    }
    vercel = {
      source  = "vercel/vercel"
      version = ">= 4.8"
    }
  }
}

provider "render" {
  api_key  = var.render_api_key
  owner_id = var.render_owner_id
}

provider "vercel" {
  api_token = var.vercel_api_token
  team      = var.vercel_team
}
```

The `cloud` block's `organization` is a placeholder string, not a variable — HCP Terraform does not
allow interpolation inside the `cloud` block. Document in `infra/terraform/README.md` (Task 4) that
the user must replace `REPLACE_WITH_TFC_ORG` with their real Terraform Cloud organization name before
`terraform init` will succeed.

- [ ] **Step 2: Create the variables file**

```hcl
# infra/terraform/variables.tf
variable "render_api_key" {
  description = "Render API key. Create at https://dashboard.render.com/u/settings#api-keys"
  type        = string
  sensitive   = true
}

variable "render_owner_id" {
  description = "Render owner (user or team) ID that owns the managed resources"
  type        = string
  sensitive   = true
}

variable "vercel_api_token" {
  description = "Vercel API token. Create at https://vercel.com/account/tokens"
  type        = string
  sensitive   = true
}

variable "vercel_team" {
  description = "Vercel team slug or ID that owns the managed projects"
  type        = string
  default     = null
}

variable "database_url" {
  description = "Full Postgres connection string for the API service (sourced from the render_postgres resource's connection_info in normal use; declared as a variable here since we are not applying yet)"
  type        = string
  sensitive   = true
  default     = null
}

variable "jwt_secret" {
  description = "JWT signing secret for the API service — must match between Render and any GitHub Actions secrets that also need it"
  type        = string
  sensitive   = true
  default     = null
}

variable "allowed_origins" {
  description = "Comma-separated list of allowed CORS origins for the API service"
  type        = string
  default     = null
}

variable "anthropic_api_key" {
  description = "Anthropic API key for the AI insights feature"
  type        = string
  sensitive   = true
  default     = null
}

variable "groq_api_key" {
  description = "Groq API key for the AI insights feature"
  type        = string
  sensitive   = true
  default     = null
}

variable "gemini_api_key" {
  description = "Gemini API key for the AI insights feature"
  type        = string
  sensitive   = true
  default     = null
}

variable "nvd_api_key" {
  description = "NVD API key for CVE enrichment (optional, raises the NVD rate limit)"
  type        = string
  sensitive   = true
  default     = null
}

variable "sentry_dsn" {
  description = "Sentry DSN for error tracking (optional)"
  type        = string
  sensitive   = true
  default     = null
}

variable "azure_subscription_id" {
  description = "Azure subscription ID for the maintainer's own smoke-test scan (NOT end-user scan credentials)"
  type        = string
  sensitive   = true
  default     = null
}

variable "azure_client_id" {
  description = "Azure service principal client ID for the maintainer's own smoke-test scan"
  type        = string
  sensitive   = true
  default     = null
}

variable "azure_tenant_id" {
  description = "Azure AD tenant ID for the maintainer's own smoke-test scan"
  type        = string
  sensitive   = true
  default     = null
}

variable "render_postgres_plan" {
  description = "Render Postgres plan tier. Confirm the real live tier against the Render dashboard before applying — this default is a guess based on docs/api-render-deploy.md, not a verified value"
  type        = string
  default     = "free"
}

variable "render_web_service_plan" {
  description = "Render web service plan tier. docs/api-render-deploy.md says \"Starter instance or higher\" — confirm the exact live tier against the dashboard before applying"
  type        = string
  default     = "starter"
}

variable "render_region" {
  description = "Render region for all managed services"
  type        = string
  default     = "oregon"
}
```

- [ ] **Step 3: Create the tfvars example (no real values, ever)**

```hcl
# infra/terraform/terraform.tfvars.example
#
# Copy this file to terraform.tfvars and fill in real values. terraform.tfvars
# is gitignored (see infra/terraform/.gitignore) — never commit real credentials.

render_api_key   = "rnd_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
render_owner_id  = "tea-xxxxxxxxxxxxxxxxxxxx"

vercel_api_token = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
vercel_team      = "your-team-slug"

database_url      = "postgresql://user:password@host:5432/openshield"
jwt_secret         = "generate-with: python -c \"import secrets; print(secrets.token_urlsafe(32))\""
allowed_origins    = "https://openshield-gules.vercel.app,https://openshield-website.vercel.app"

anthropic_api_key = ""
groq_api_key      = ""
gemini_api_key    = ""
nvd_api_key       = ""
sentry_dsn        = ""

azure_subscription_id = ""
azure_client_id       = ""
azure_tenant_id       = ""

render_postgres_plan    = "free"
render_web_service_plan = "starter"
render_region            = "oregon"
```

- [ ] **Step 4: Gitignore real tfvars and local state**

```
# infra/terraform/.gitignore
terraform.tfvars
*.tfstate
*.tfstate.*
.terraform/
.terraform.lock.hcl
```

`.terraform.lock.hcl` is deliberately ignored here since this PR never runs a real `terraform init`
against a live backend to generate a committed lock file — see Task 5's verification note.

- [ ] **Step 5: Commit**

```bash
git add infra/terraform/versions.tf infra/terraform/variables.tf infra/terraform/terraform.tfvars.example infra/terraform/.gitignore
git commit -m "infra: add Terraform provider/backend skeleton for Render and Vercel"
```

---

### Task 2: Render resources — Postgres, web service, env group

**Files:**
- Create: `infra/terraform/render.tf`

**Interfaces:**
- Consumes: `var.render_postgres_plan`, `var.render_web_service_plan`, `var.render_region`,
  `var.database_url`, `var.jwt_secret`, `var.allowed_origins`, `var.anthropic_api_key`,
  `var.groq_api_key`, `var.gemini_api_key`, `var.nvd_api_key`, `var.sentry_dsn`,
  `var.azure_subscription_id`, `var.azure_client_id`, `var.azure_tenant_id` (all from Task 1).
- Produces: `render_postgres.db`, `render_web_service.api`, `render_env_group.api_secrets` — Task 4's
  `outputs.tf` references these.

- [ ] **Step 1: Write the Postgres resource**

```hcl
# infra/terraform/render.tf

resource "render_postgres" "db" {
  name   = "openshield-db"
  plan   = var.render_postgres_plan
  region = var.render_region
  version = "16"

  database_name = "openshield"
  database_user = "openshield"
}
```

- [ ] **Step 2: Write the shared env group for secret-shaped values**

```hcl
resource "render_env_group" "api_secrets" {
  name = "openshield-api-secrets"

  env_vars = {
    JWT_SECRET             = { value = var.jwt_secret }
    ANTHROPIC_API_KEY      = { value = var.anthropic_api_key }
    GROQ_API_KEY           = { value = var.groq_api_key }
    GEMINI_API_KEY         = { value = var.gemini_api_key }
    NVD_API_KEY            = { value = var.nvd_api_key }
    SENTRY_DSN             = { value = var.sentry_dsn }
    AZURE_SUBSCRIPTION_ID  = { value = var.azure_subscription_id }
    AZURE_CLIENT_ID        = { value = var.azure_client_id }
    AZURE_TENANT_ID        = { value = var.azure_tenant_id }
  }
}
```

Note: `AZURE_CLIENT_SECRET` is deliberately absent from this env group. It stays out of Terraform
entirely — the whole point of this issue is to stop needing it in the smoke-test workflow, and the
Render web service's own Azure credentials (for the product's real scanning feature) are configured
directly by the maintainer in the Render dashboard, not through this shared secrets group, since they
are operationally distinct from the CI smoke-test identity (see Global Constraints).

- [ ] **Step 3: Write the web service resource**

```hcl
resource "render_web_service" "api" {
  name   = "openshield-api"
  plan   = var.render_web_service_plan
  region = var.render_region

  runtime_source = {
    docker = {
      repo_url        = "https://github.com/openshield-org/openshield"
      branch           = "main"
      dockerfile_path  = "Dockerfile"
    }
  }

  start_command = "./startup.sh"

  env_vars = {
    DATABASE_URL     = { value = var.database_url }
    ALLOWED_ORIGINS  = { value = var.allowed_origins }
    OPENSHIELD_ENV   = { value = "production" }
    RENDER           = { value = "true" }
  }
}

resource "render_env_group_link" "api_secrets_link" {
  env_group_id = render_env_group.api_secrets.id
  service_ids  = [render_web_service.api.id]
}
```

`OPENSHIELD_ENV=production` and `RENDER=true` are set explicitly here because `api/app.py`'s
`_is_production()` checks exactly these two environment variables to enforce the strong-`JWT_SECRET`
fail-closed behavior described in `docs/api-render-deploy.md`.

- [ ] **Step 4: Commit**

```bash
git add infra/terraform/render.tf
git commit -m "infra: define Render Postgres, web service, and shared secrets env group"
```

---

### Task 3: Vercel resources — dashboard and website projects

**Files:**
- Create: `infra/terraform/vercel.tf`

**Interfaces:**
- Consumes: nothing beyond the `vercel` provider configured in Task 1.
- Produces: `vercel_project.dashboard`, `vercel_project.website` — Task 4's `outputs.tf` references
  these.

- [ ] **Step 1: Write the dashboard (frontend/) project**

```hcl
# infra/terraform/vercel.tf

resource "vercel_project" "dashboard" {
  name            = "openshield-dashboard"
  framework       = "vite"
  root_directory  = "frontend"

  git_repository = {
    type = "github"
    repo = "openshield-org/openshield"
  }

  environment = [
    {
      key       = "VITE_API_BASE_URL"
      value     = "https://openshield-api.onrender.com"
      target    = ["production", "preview"]
      sensitive = false
    }
  ]
}
```

`framework = "vite"` matches `frontend/package.json`'s `vite`/`vite build` scripts confirmed during
design. `name` uses a descriptive slug rather than assuming the exact live project name/URL
(`openshield-gules`, per `README.md`) since Vercel project names become part of the deployment URL
and renaming an existing live project via Terraform on first apply could change that URL — flagged in
`infra/terraform/README.md` (Task 4) as something the user must reconcile (likely via
`terraform import` against the *existing* project rather than creating a new one).

- [ ] **Step 2: Write the website project**

```hcl
resource "vercel_project" "website" {
  name           = "openshield-website"
  root_directory = "website"

  git_repository = {
    type = "github"
    repo = "openshield-org/openshield"
  }
}
```

No `framework` value — the website is static HTML with a Tailwind CDN `<script>` tag (confirmed via
`website/README.md`, no build step), matching Vercel's "Other" framework preset which is the default
when `framework` is omitted.

- [ ] **Step 3: Commit**

```bash
git add infra/terraform/vercel.tf
git commit -m "infra: define Vercel projects for the dashboard and website"
```

---

### Task 4: Outputs, README, and local validation

**Files:**
- Create: `infra/terraform/outputs.tf`
- Create: `infra/terraform/README.md`

**Interfaces:**
- Consumes: `render_postgres.db`, `render_web_service.api`, `vercel_project.dashboard`,
  `vercel_project.website` (all from Tasks 2–3).

- [ ] **Step 1: Write non-sensitive outputs**

```hcl
# infra/terraform/outputs.tf
output "api_service_url" {
  description = "Live URL of the Render web service"
  value       = render_web_service.api.url
}

output "api_service_id" {
  description = "Render service ID, useful for the deploy-hook API (see #157)"
  value       = render_web_service.api.id
}

output "postgres_id" {
  description = "Render Postgres instance ID"
  value       = render_postgres.db.id
}

output "dashboard_project_id" {
  description = "Vercel project ID for the dashboard"
  value       = vercel_project.dashboard.id
}

output "website_project_id" {
  description = "Vercel project ID for the website"
  value       = vercel_project.website.id
}
```

No `connection_info` or other sensitive attributes are output here — Terraform Cloud state already
holds them encrypted at rest, but outputs are easy to accidentally print in CI logs, so keep this
list to identifiers and URLs only.

- [ ] **Step 2: Write the module README**

```markdown
# infra/terraform/README.md

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
```

- [ ] **Step 3: Validate locally (no credentials needed for fmt/validate)**

Terraform's `cloud` block requires `terraform login` or a `TF_API_TOKEN` to fully `init` against the
real backend, which isn't available. Validate structurally instead, using a local backend override
that isn't committed:

```bash
cd infra/terraform
echo 'terraform { backend "local" {} }' > override.tf
terraform init -backend=false
terraform fmt -check
terraform validate
rm override.tf
```

Run: the four commands above, in order, from `infra/terraform/`.

Expected: `terraform init -backend=false` downloads the `render` and `vercel` providers and reports
success (`Terraform has been successfully initialized!`). `terraform fmt -check` outputs nothing
(exit 0). `terraform validate` outputs `Success! The configuration is valid.`. Delete `override.tf`
afterward — it must never be committed (it exists only to let `validate` run without a real Terraform
Cloud login; the committed `versions.tf` keeps the real `cloud` block).

If `terraform validate` reports an error, fix the offending block in `render.tf`/`vercel.tf`/
`variables.tf` and re-run before moving on — do not commit invalid HCL.

- [ ] **Step 4: Commit**

```bash
git add infra/terraform/outputs.tf infra/terraform/README.md
git commit -m "infra: add Terraform outputs and module README"
```

---

### Task 5: `terraform-plan.yml` GitHub Actions workflow

**Files:**
- Create: `.github/workflows/terraform-plan.yml`

**Interfaces:**
- Consumes: `infra/terraform/**` (path filter), optional `secrets.TF_API_TOKEN`.

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/terraform-plan.yml
name: Terraform Plan

on:
  pull_request:
    paths:
      - "infra/terraform/**"

permissions:
  contents: read
  pull-requests: write

jobs:
  plan:
    name: Terraform fmt / validate / plan
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: infra/terraform
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: "~1.6"
          terraform_wrapper: false

      - name: Terraform fmt
        run: terraform fmt -check -recursive

      - name: Check for Terraform Cloud token
        id: check_token
        run: |
          if [ -n "${{ secrets.TF_API_TOKEN }}" ]; then
            echo "has_token=true" >> "$GITHUB_OUTPUT"
          else
            echo "has_token=false" >> "$GITHUB_OUTPUT"
          fi

      - name: Terraform init (no backend, structural check only)
        if: steps.check_token.outputs.has_token == 'false'
        run: |
          echo 'terraform { backend "local" {} }' > override.tf
          terraform init -backend=false
          rm override.tf

      - name: Terraform validate (no credentials)
        if: steps.check_token.outputs.has_token == 'false'
        run: |
          echo "TF_API_TOKEN not configured — skipping real plan, running structural validation only."
          echo 'terraform { backend "local" {} }' > override.tf
          terraform init -backend=false
          terraform validate
          rm override.tf

      - name: Terraform init (real backend)
        if: steps.check_token.outputs.has_token == 'true'
        env:
          TF_TOKEN_app_terraform_io: ${{ secrets.TF_API_TOKEN }}
        run: terraform init

      - name: Terraform plan
        if: steps.check_token.outputs.has_token == 'true'
        env:
          TF_TOKEN_app_terraform_io: ${{ secrets.TF_API_TOKEN }}
        run: terraform plan -no-color
        continue-on-error: false
```

The `TF_TOKEN_app_terraform_io` environment variable name is Terraform's documented convention for
supplying a Terraform Cloud API token for the `app.terraform.io` host without a config file — dots in
the hostname become underscores in the env var name.

- [ ] **Step 2: Validate the workflow YAML locally**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/terraform-plan.yml'))"` (from
the repo root, using the same Python interpreter the rest of this repo's tooling uses).

Expected: no output, exit code 0 (valid YAML parses silently).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/terraform-plan.yml
git commit -m "ci: add Terraform fmt/validate/plan workflow for infra PRs"
```

---

### Task 6: Switch `deploy.yml`'s Azure auth to OIDC

**Files:**
- Modify: `.github/workflows/deploy.yml`

**Interfaces:**
- None — this task only changes workflow YAML, no Terraform or Python interfaces involved.

- [ ] **Step 1: Add the `permissions` block and `azure/login` step**

Locate the `jobs.deploy` block in `.github/workflows/deploy.yml`. Add a top-level `permissions` key
(sibling of `on:` and `jobs:`), and insert an `azure/login@v3` step immediately before the existing
"Run smoke tests against live deployment" step:

```yaml
permissions:
  id-token: write
  contents: read
```

```yaml
      - name: Azure login (OIDC)
        if: steps.check_config.outputs.is_configured == 'true' || github.event_name == 'workflow_dispatch'
        uses: azure/login@v3
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}
```

- [ ] **Step 2: Remove `AZURE_CLIENT_SECRET` from the smoke-test step's env block**

In the same file, find the "Run smoke tests against live deployment" step's `env:` block and delete
the `AZURE_CLIENT_SECRET: ${{ secrets.AZURE_CLIENT_SECRET }}` line. Leave
`AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID`, and `AZURE_TENANT_ID` as they are — `DefaultAzureCredential()`
still needs these three to select `WorkloadIdentityCredential` from its chain; only the secret itself
is no longer needed, since `azure/login@v3` (Step 1) has already exchanged the workflow's OIDC token
for a short-lived Azure token and exported `AZURE_FEDERATED_TOKEN_FILE` into the job environment.

- [ ] **Step 3: Validate the workflow YAML locally**

Run: `python -c "import yaml; yaml.safe_load(open('.github/workflows/deploy.yml'))"` from the repo
root.

Expected: no output, exit code 0.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/deploy.yml
git commit -m "ci: authenticate to Azure via OIDC instead of a long-lived client secret"
```

---

### Task 7: Document the one-time Azure AD federated credential setup

**Files:**
- Create: `docs/ci-oidc-setup.md`

**Interfaces:**
- None — documentation only.

- [ ] **Step 1: Write the doc**

```markdown
# GitHub OIDC Federation for Azure (CI smoke tests)

This replaces the long-lived `AZURE_CLIENT_SECRET` GitHub secret used by `deploy.yml`'s smoke-test
job with short-lived tokens minted per workflow run via GitHub's OIDC provider. It applies **only**
to the maintainer's own smoke-test Azure subscription in CI — it has no effect on how the deployed
product authenticates to end users' own Azure subscriptions when they configure OpenShield to scan
their environment (that always uses credentials the end user supplies).

## Prerequisite

The existing `openshield-scanner` service principal from `docs/azure-setup.md` (Reader role on the
maintainer's test subscription). You are adding a federated credential to it, not creating a new
principal.

## One-time setup (run once, by whoever holds Azure AD admin rights)

```bash
# Get the existing app's object ID
APP_ID=$(az ad app list --display-name "openshield-scanner" --query "[0].id" --output tsv)

# Trust GitHub Actions runs from this repo's dev and main branches
az ad app federated-credential create \
  --id "$APP_ID" \
  --parameters '{
    "name": "openshield-dev-branch",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:openshield-org/openshield:ref:refs/heads/dev",
    "audiences": ["api://AzureADTokenExchange"]
  }'

az ad app federated-credential create \
  --id "$APP_ID" \
  --parameters '{
    "name": "openshield-main-branch",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:openshield-org/openshield:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

Add one more `federated-credential create` call per branch or trigger type you need — for example,
`subject": "repo:openshield-org/openshield:pull_request"` if `deploy.yml` is ever triggered on pull
requests, not just `dev`/`main` pushes. `deploy.yml` currently only runs on `workflow_dispatch`, so
confirm which ref it's dispatched against and add a matching federated credential subject for that
ref before relying on this in production.

## Verifying it works

1. Trigger `deploy.yml` manually (`workflow_dispatch`) from the Actions tab.
2. Confirm the "Azure login (OIDC)" step succeeds without any `client-secret` input.
3. Confirm the smoke test's real-scan steps (TC-13/TC-14) still pass — this proves
   `DefaultAzureCredential()` picked up the federated token correctly.

## Last step — only after verification passes

Delete the `AZURE_CLIENT_SECRET` repository secret (**Settings → Secrets and variables → Actions**).
This is a manual, deliberate step — do not automate it, and do not do it before confirming the OIDC
login actually works, or the smoke-test workflow breaks with no working fallback.
```

- [ ] **Step 2: Commit**

```bash
git add docs/ci-oidc-setup.md
git commit -m "docs: document one-time Azure AD federated credential setup for OIDC"
```

---

### Task 8: Update the GitHub Secrets table and add the secrets inventory doc

**Files:**
- Modify: `docs/api-render-deploy.md`
- Create: `docs/secrets-inventory.md`

**Interfaces:**
- None — documentation only.

- [ ] **Step 1: Update the GitHub Secrets table in `docs/api-render-deploy.md`**

Find the table under "### 4.3 Configure GitHub Secrets". Remove the `AZURE_CLIENT_SECRET` row
entirely. The table's remaining Azure rows (`AZURE_SUBSCRIPTION_ID`, `AZURE_CLIENT_ID`,
`AZURE_TENANT_ID`) stay as-is, since OIDC still needs them.

Add one line directly below the table:

```markdown
> As of #160, Azure authentication for real-scan smoke tests uses GitHub OIDC federation
> instead of a stored client secret. See `docs/ci-oidc-setup.md` for the one-time setup.
```

- [ ] **Step 2: Write the secrets inventory doc**

```markdown
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
```

- [ ] **Step 3: Commit**

```bash
git add docs/api-render-deploy.md docs/secrets-inventory.md
git commit -m "docs: update secrets table for OIDC, add secrets inventory doc"
```

---

### Task 9: Full verification pass

**Files:** none created or modified — this task only runs checks.

- [ ] **Step 1: Re-run Terraform structural validation**

```bash
cd infra/terraform
echo 'terraform { backend "local" {} }' > override.tf
terraform init -backend=false
terraform fmt -check -recursive
terraform validate
rm override.tf
cd ../..
```

Expected: all three commands succeed with no errors, matching Task 4 Step 3's expected output.

- [ ] **Step 2: Validate every touched/created YAML workflow file**

```bash
python -c "
import yaml
for f in ['.github/workflows/deploy.yml', '.github/workflows/terraform-plan.yml']:
    yaml.safe_load(open(f))
    print(f, 'OK')
"
```

Expected: both files print `OK`, no exceptions.

- [ ] **Step 3: Run the full existing test suite and lint to confirm zero application-code impact**

```bash
python -m ruff check .
python -m ruff format --check .
python -m pytest -q
```

Expected: ruff reports no issues in any file this plan touched (it touches no `.py` files at all —
this step exists to catch the unlikely case of an accidental edit, not because Terraform/YAML/Markdown
changes should affect Python lint or tests). Pytest should show the same pass count and the same 1–2
pre-existing, unrelated local failures this repo's test suite always shows (a local
vector-store-not-built error and/or an environment-dependent Azure rule test) — no new failures.

- [ ] **Step 4: Review the full diff before opening the PR**

```bash
git diff origin/dev...HEAD --stat
```

Expected: only the files this plan created/modified appear — `infra/terraform/**`,
`.github/workflows/terraform-plan.yml`, `.github/workflows/deploy.yml`,
`docs/ci-oidc-setup.md`, `docs/secrets-inventory.md`, `docs/api-render-deploy.md`, and the two
`docs/superpowers/**` files from the brainstorming/planning phase. No unrelated files.

---

## Self-Review Notes

- **Spec coverage:** `infra/terraform/` root (Tasks 1–4) ✓. Remote state / plan-on-PR (Task 5) ✓.
  GitHub OIDC federation (Tasks 6–7) ✓. Secrets inventory (Task 8) ✓. Current-topology-only scope,
  `render.yaml` overlap flagged (Task 4's README) ✓. No `terraform apply`, no secret deletion (Global
  Constraints, Task 7) ✓.
- **Type/name consistency check:** `render_web_service.api`, `render_postgres.db`,
  `render_env_group.api_secrets`, `vercel_project.dashboard`, `vercel_project.website` are the only
  resource names used anywhere in the plan (Tasks 2, 3, 4) — verified consistent across `render.tf`,
  `vercel.tf`, and `outputs.tf`. Variable names in `variables.tf` (Task 1) match every reference in
  `render.tf` (Task 2) and `terraform.tfvars.example` (Task 1) one-for-one.
