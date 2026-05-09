# Sentinel Integration Setup Guide

This guide configures Microsoft Sentinel ingestion for findings produced by OpenShield. The ingestion client is `sentinel/ingest.py`.

---

## Prerequisites

- Azure account
- Azure CLI installed and logged in
- Python 3.9+
- `requests` installed through `pip install -r requirements.txt`

---

## Part 1 - Create a Log Analytics Workspace

```bash
az group create \
  --name openshield-rg \
  --location uksouth

az monitor log-analytics workspace create \
  --resource-group openshield-rg \
  --workspace-name openshield-laws \
  --location uksouth \
  --retention-time 30
```

Get the workspace ID:

```bash
az monitor log-analytics workspace show \
  --resource-group openshield-rg \
  --workspace-name openshield-laws \
  --query customerId \
  --output tsv
```

Get the shared key:

```bash
az monitor log-analytics workspace get-shared-keys \
  --resource-group openshield-rg \
  --workspace-name openshield-laws \
  --query primarySharedKey \
  --output tsv
```

---

## Part 2 - Activate Sentinel

```bash
az extension add --name sentinel

az sentinel onboarding-state create \
  --resource-group openshield-rg \
  --workspace-name openshield-laws \
  --name default
```

---

## Part 3 - Set Environment Variables

`sentinel/ingest.py` reads these variables:

```bash
export SENTINEL_WORKSPACE_ID="your-workspace-id"
export SENTINEL_SHARED_KEY="your-shared-key"
export SENTINEL_LOG_TYPE="OpenShieldFindings"
```

`SENTINEL_LOG_TYPE` is optional. If it is not set, the script uses `OpenShieldFindings`.

---

## Part 4 - Run Ingestion

The ingestion script accepts:

```bash
python3 sentinel/ingest.py <findings-json-path> <scan-id>
```

If no path is supplied, it defaults to `scanner/output/test_findings.json`. If no scan ID is supplied, it generates one using the current UTC timestamp.

Generate test findings:

```bash
mkdir -p scanner/output
python3 sentinel/tests/generate_test_findings.py
```

Push findings to Sentinel:

```bash
python3 sentinel/ingest.py scanner/output/test_findings.json scan-001
```

The script accepts either a JSON list of findings or an object with a `findings` array. It normalises each record, signs the request with `SENTINEL_SHARED_KEY`, and posts to the Log Analytics Data Collector API.

---

## Part 5 - Verify in Sentinel Logs

Run this query in Log Analytics:

```kql
OpenShieldFindings_CL | take 10
```

If rows appear, ingestion is working.

---

## Part 6 - Deploy KQL Rules in Sentinel Analytics

Go to Microsoft Sentinel or Microsoft Defender XDR and navigate to Analytics. Create a scheduled query rule for each file in `sentinel/rules/`:

| Rule file | Severity | Schedule |
|---|---|---|
| `high_severity_finding.kql` | High | Every 1 hour |
| `misconfiguration_wave.kql` | High | Every 2 hours |
| `persistent_misconfiguration.kql` | Medium | Every 24 hours |
| `new_resource_type_critical.kql` | Critical | Every 1 hour |

Set the alert threshold to greater than 0 for all rules.

---

## Part 7 - Verify Incidents

Go to Incidents in Sentinel or Microsoft Defender XDR. After the scheduled analytics rules run, OpenShield incidents should appear for matching findings.
