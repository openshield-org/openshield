# OpenShield Architecture

## Overview

OpenShield is a modular, open source Cloud Security Posture Management (CSPM) platform for Azure. It continuously scans your Azure subscription against a library of security rules, maps every finding to compliance frameworks (CIS, NIST CSF, ISO 27001), and exposes results via a REST API consumed by a React dashboard.

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                       React Dashboard                            │
│              (Azure Static Web Apps — Free tier)                 │
└────────────────────────────┬─────────────────────────────────────┘
                             │ HTTPS / JWT
┌────────────────────────────▼─────────────────────────────────────┐
│                    Flask REST API  (api/)                         │
│                                                                  │
│  GET  /api/findings          GET  /api/score                     │
│  GET  /api/findings/<id>     GET  /api/compliance/<framework>    │
│  GET  /api/scans             POST /api/scans/trigger             │
└───────────┬──────────────────────────────────┬───────────────────┘
            │                                  │
┌───────────▼──────────────┐   ┌───────────────▼───────────────────┐
│     Scanner Engine        │   │     Compliance Mapper              │
│     (scanner/)            │   │     (compliance/frameworks/)       │
│                           │   │                                    │
│  ScanEngine               │   │  cis_azure_benchmark.json          │
│    └── load_rules()       │   │  nist_csf.json                     │
│    └── run_scan()         │   │  iso27001.json                     │
└───────────┬───────────────┘   └────────────────────────────────────┘
            │
┌───────────▼──────────────────────────────────────────────────────┐
│                   Rule Modules (scanner/rules/)                   │
│                                                                   │
│  az_stor_001.py   az_net_001.py   az_idn_001.py   az_db_001.py  │
│  az_stor_002.py   az_net_002.py   az_idn_002.py   az_db_002.py  │
│                   az_cmp_001.py   az_kv_001.py                   │
└───────────┬───────────────────────────────────────────────────────┘
            │ calls
┌───────────▼──────────────────────────────────────────────────────┐
│                AzureClient (scanner/azure_client.py)             │
│                                                                   │
│  DefaultAzureCredential                                          │
│  StorageManagementClient   NetworkManagementClient               │
│  ComputeManagementClient   PostgreSQLManagementClient            │
│  SqlManagementClient       KeyVaultManagementClient              │
│  AuthorizationManagementClient   MS Graph REST API               │
└───────────┬───────────────────────────────────────────────────────┘
            │ Azure SDK calls
┌───────────▼──────────────────────────────────────────────────────┐
│                  Azure Subscription (target)                     │
└──────────────────────────────────────────────────────────────────┘
            │
┌───────────▼──────────────────────────────────────────────────────┐
│                 PostgreSQL Database                               │
│           (findings, scans, rules tables)                        │
└──────────────────────────────────────────────────────────────────┘
```

---

## How the Scanner Works

### 1. Initialisation

```python
engine = ScanEngine(subscription_id="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
```

`ScanEngine.__init__` creates an `AzureClient` using `DefaultAzureCredential`, which automatically resolves credentials from (in order): environment variables, managed identity, Azure CLI, or VS Code login.

### 2. Rule Loading

```python
engine.load_rules()
```

`load_rules()` iterates over every `*.py` file in `scanner/rules/` that does not start with `_`. It uses Python's `importlib.util` to load each file as a module and checks that the module exposes a `scan()` function. This means:

- **Adding a rule requires no code change to the engine** — drop a file into `scanner/rules/` and it is automatically discovered on next startup.
- Rules that fail to load (syntax errors, missing imports) are logged and skipped. The remaining rules still run.

### 3. Scan Execution

```python
result = engine.run_scan()
```

`run_scan()` iterates through all loaded rule modules, calling `module.scan(azure_client, subscription_id)` for each. Individual rule failures are caught and logged without stopping the scan. The engine collects all findings and returns a structured result dict.

### 4. Finding Schema

Every finding returned by a rule must conform to this schema:

```python
{
    "rule_id":       str,   # e.g. "AZ-STOR-001"
    "rule_name":     str,
    "severity":      str,   # HIGH | MEDIUM | LOW | INFO
    "category":      str,   # Storage | Network | Identity | Database | Compute | KeyVault
    "resource_id":   str,   # full Azure resource ID
    "resource_name": str,
    "resource_type": str,   # e.g. "Microsoft.Storage/storageAccounts"
    "description":   str,
    "remediation":   str,
    "playbook":      str,   # path to the CLI remediation script
    "frameworks":    dict,  # {"CIS": "3.5", "NIST": "PR.AC-3", "ISO27001": "A.9.4.1"}
    "detected_at":   str,   # ISO 8601, added by engine
    "scan_id":       str,   # UUID, added by engine
}
```

---

## How Findings Flow to the API

```
run_scan()
    → findings[] in memory
    → db.save_scan(result)           # persists to PostgreSQL
    → return scan result JSON

GET /api/findings
    → db.get_findings(filters)       # reads from PostgreSQL
    → returns JSON array

GET /api/score
    → db.get_score()                 # severity-weighted 0-100
    → returns {"score": 82}

GET /api/compliance/cis
    → db.get_compliance_score("cis") # joins DB findings with CIS JSON
    → returns per-control pass/fail breakdown
```

---

## How Rules Are Loaded Dynamically

The engine uses Python's `importlib` to load rule files at runtime. No registry or central list is needed:

```python
for rule_path in sorted(RULES_DIR.glob("*.py")):
    if rule_path.name.startswith("_"):
        continue
    spec = importlib.util.spec_from_file_location(rule_path.stem, rule_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if callable(getattr(module, "scan", None)):
        self.rules.append(module)
```

Each rule module is a plain Python file — no base class, no registration decorator. The only contract is the `scan(azure_client, subscription_id)` function signature.

---

## How Sentinel Integration Works

> **Note:** Sentinel push is handled by a separate team. This section documents the integration point.

After `run_scan()` returns, findings can be forwarded to Microsoft Sentinel via the Azure Monitor Ingestion API. The `sentinel/` directory contains the KQL detection rules and the ingestion client configuration.

The flow:
1. `POST /api/scans/trigger` → scan completes → findings in DB
2. A Sentinel push worker (separate process or Azure Function) polls the DB for new findings
3. New findings are batched and sent to a Log Analytics Workspace via `azure-monitor-ingestion`
4. KQL detection rules in Sentinel fire alerts on HIGH-severity findings

The required environment variable is `SENTINEL_WORKSPACE_ID` (see `.env.example`).

---

## Configuration

All runtime configuration is provided via environment variables (see `.env.example`):

| Variable | Description |
|---|---|
| `AZURE_SUBSCRIPTION_ID` | Target subscription to scan |
| `AZURE_CLIENT_ID` | Service principal client ID |
| `AZURE_CLIENT_SECRET` | Service principal client secret |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `DATABASE_URL` | PostgreSQL connection string |
| `JWT_SECRET` | Secret used to sign/verify API JWTs |
| `SENTINEL_WORKSPACE_ID` | Log Analytics workspace ID for Sentinel push |
