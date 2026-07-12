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
`"subject": "repo:openshield-org/openshield:pull_request"` if `deploy.yml` is ever triggered on pull
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
