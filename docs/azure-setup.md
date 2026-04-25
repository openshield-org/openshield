# Azure Setup Guide

This guide gets you from zero to a running OpenShield scan in under 20 minutes using a free Azure account.

---

## Step 1 — Create a Free Azure Account

1. Go to [azure.microsoft.com/free](https://azure.microsoft.com/free) and click **Start free**.
2. Sign in with a Microsoft account (or create one).
3. Complete the sign-up — you will receive $200 in free credits and access to free-tier services.
4. After sign-up, navigate to the [Azure Portal](https://portal.azure.com).

---

## Step 2 — Get Your Subscription ID

1. In the Azure Portal, search for **Subscriptions** in the top search bar.
2. Click on your subscription name.
3. Copy the **Subscription ID** (a UUID like `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).

You will need this value for `AZURE_SUBSCRIPTION_ID` in your `.env` file.

---

## Step 3 — Create a Service Principal with Reader Role

OpenShield only needs read access to scan your subscription. Use the Azure CLI:

```bash
# Install Azure CLI if you haven't already
# https://learn.microsoft.com/en-us/cli/azure/install-azure-cli

# Login
az login

# Create the service principal with Reader role
az ad sp create-for-rbac \
  --name "openshield-scanner" \
  --role Reader \
  --scopes /subscriptions/<YOUR_SUBSCRIPTION_ID> \
  --output json
```

This command outputs JSON like:

```json
{
  "appId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "displayName": "openshield-scanner",
  "password": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "tenant": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
}
```

Map these values:
- `appId` → `AZURE_CLIENT_ID`
- `password` → `AZURE_CLIENT_SECRET`
- `tenant` → `AZURE_TENANT_ID`

> **Important:** The `password` is only shown once. Copy it immediately.

---

## Step 4 — Grant Additional Read Permissions (Optional)

For the Conditional Access MFA rule (AZ-IDN-002), the service principal needs the
`Policy.Read.All` Microsoft Graph API permission:

```bash
# Get the service principal object ID
SP_OBJECT_ID=$(az ad sp show --id <YOUR_APP_ID> --query id --output tsv)

# Grant Policy.Read.All application permission
# This requires a Global Administrator to consent
az rest \
  --method POST \
  --uri "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_OBJECT_ID/appRoleAssignments" \
  --body '{
    "principalId": "'$SP_OBJECT_ID'",
    "resourceId": "<GRAPH_SERVICE_PRINCIPAL_ID>",
    "appRoleId": "246dd0d5-5bd0-4def-940b-0421030a5b68"
  }'
```

If you skip this step, AZ-IDN-002 will produce a finding by default (it cannot verify MFA status without Graph access).

---

## Step 5 — Configure Your .env File

Copy the example and fill in your values:

```bash
cp .env.example .env
```

Edit `.env`:

```
AZURE_SUBSCRIPTION_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
AZURE_CLIENT_SECRET=your-client-secret-from-step-3
AZURE_TENANT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
DATABASE_URL=postgresql://openshield:openshield@localhost:5432/openshield
JWT_SECRET=your-random-secret-at-least-32-chars
SENTINEL_WORKSPACE_ID=
```

---

## Step 6 — Start a Local PostgreSQL Database

```bash
# Option A: Docker (easiest)
docker run --name openshield-db \
  -e POSTGRES_USER=openshield \
  -e POSTGRES_PASSWORD=openshield \
  -e POSTGRES_DB=openshield \
  -p 5432:5432 \
  -d postgres:15

# Option B: Homebrew (macOS)
brew install postgresql@15
brew services start postgresql@15
createdb openshield
```

The `DatabaseManager.create_tables()` call in the scan trigger will create the schema automatically on first run.

---

## Step 7 — Run Your First Scan

```bash
# From the openshield/ directory
cd openshield

# Install dependencies
pip install -r requirements.txt

# Run the scanner directly
python -c "
from dotenv import load_dotenv; load_dotenv()
import json, os
from scanner.engine import ScanEngine
engine = ScanEngine(os.environ['AZURE_SUBSCRIPTION_ID'])
result = engine.run_scan()
print(json.dumps(result, indent=2))
"
```

Or trigger via the API:

```bash
# Start the API server
FLASK_APP=api/app.py flask run

# Trigger a scan
curl -X POST http://localhost:5000/api/scans/trigger \
  -H "Authorization: Bearer <YOUR_JWT>" \
  -H "Content-Type: application/json" \
  -d '{"subscription_id": "your-subscription-id"}'
```

---

## Step 8 — Activate the Microsoft Sentinel 90-Day Trial (Optional)

Microsoft Sentinel includes a 90-day free trial for new Log Analytics workspaces.

1. In the Azure Portal, search for **Microsoft Sentinel**.
2. Click **Create Microsoft Sentinel**.
3. Click **Create a new workspace** and fill in:
   - Workspace name: `openshield-logs`
   - Region: choose the same region as your resources
4. Click **Add Microsoft Sentinel** — the 90-day trial activates automatically.
5. Copy the **Workspace ID** from the workspace Overview page.
6. Add it to your `.env`: `SENTINEL_WORKSPACE_ID=<workspace-id>`

> **Cost after trial:** ~$2.76/GB ingested. For a small subscription with few findings, this is negligible.

---

## Step 9 — Create a Log Analytics Workspace (for SQL Auditing)

The AZ-DB-002 remediation playbook writes SQL audit logs to a storage account. To route them to Log Analytics instead:

1. Go to your SQL server in the portal.
2. Under **Security**, click **Auditing**.
3. Set **Auditing** to **ON**.
4. Check **Log Analytics** and select your `openshield-logs` workspace.
5. Click **Save**.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `DefaultAzureCredential` fails | Run `az login` in the terminal, or verify env vars are set |
| `AZURE_CLIENT_SECRET` rejected | The secret may have expired — rotate it with `az ad sp credential reset` |
| `psycopg2.OperationalError` | Check your PostgreSQL container is running and `DATABASE_URL` is correct |
| Empty findings | Verify the service principal has `Reader` role on the subscription |
| AZ-IDN-002 always fires | The service principal needs `Policy.Read.All` Graph permission — see Step 4 |
