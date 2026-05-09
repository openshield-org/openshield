# API Reference

The OpenShield API is a Flask app registered in `api/app.py`. `/health` is public. All `/api/*` routes require an `Authorization: Bearer <jwt>` header signed with `JWT_SECRET`.

---

## GET /health

Health check for the API process.

Query parameters: none

Example response:

```json
{
  "status": "ok"
}
```

---

## GET /api/findings

Returns findings, optionally filtered by severity, category, rule ID, or scan ID.

Query parameters:

| Name | Description |
|---|---|
| `severity` | `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `category` | Rule category, such as `Storage`, `Network`, `Identity`, `Database`, `Compute`, or `Key Vault` |
| `rule_id` | Rule ID, such as `AZ-STOR-001` |
| `scan_id` | UUID of a specific scan |

Example response:

```json
{
  "count": 1,
  "findings": [
    {
      "id": 42,
      "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a",
      "rule_id": "AZ-STOR-001",
      "rule_name": "Public Blob Access Enabled on Storage Account",
      "severity": "HIGH",
      "category": "Storage",
      "resource_id": "/subscriptions/example/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/example",
      "resource_name": "example",
      "resource_type": "Microsoft.Storage/storageAccounts",
      "description": "Storage accounts with public blob access enabled allow unauthenticated read access to blob data over the internet.",
      "remediation": "Disable public blob access on the storage account.",
      "playbook": "playbooks/cli/fix_az_stor_001.sh",
      "frameworks": {
        "CIS": "3.5",
        "NIST": "PR.AC-3",
        "ISO27001": "A.9.4.1"
      },
      "metadata": {},
      "detected_at": "2026-05-09T12:00:00Z"
    }
  ]
}
```

---

## GET /api/findings/&lt;finding_id&gt;

Returns one finding by integer ID.

Query parameters: none

Example response:

```json
{
  "id": 42,
  "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a",
  "rule_id": "AZ-STOR-001",
  "rule_name": "Public Blob Access Enabled on Storage Account",
  "severity": "HIGH",
  "category": "Storage",
  "resource_id": "/subscriptions/example/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/example",
  "resource_name": "example",
  "resource_type": "Microsoft.Storage/storageAccounts",
  "description": "Storage accounts with public blob access enabled allow unauthenticated read access to blob data over the internet.",
  "remediation": "Disable public blob access on the storage account.",
  "playbook": "playbooks/cli/fix_az_stor_001.sh",
  "frameworks": {
    "CIS": "3.5",
    "NIST": "PR.AC-3",
    "ISO27001": "A.9.4.1"
  },
  "metadata": {},
  "detected_at": "2026-05-09T12:00:00Z"
}
```

Not found response:

```json
{
  "error": "Finding not found"
}
```

---

## GET /api/scans

Returns historical scan records ordered by most recent first.

Query parameters: none

Example response:

```json
{
  "count": 1,
  "scans": [
    {
      "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a",
      "subscription_id": "00000000-0000-0000-0000-000000000000",
      "started_at": "2026-05-09T12:00:00Z",
      "completed_at": "2026-05-09T12:02:00Z",
      "total_findings": 3
    }
  ]
}
```

---

## POST /api/scans/trigger

Runs a synchronous scan and saves the result to PostgreSQL. The request body may include `subscription_id`; otherwise the API uses `AZURE_SUBSCRIPTION_ID`.

Request body:

```json
{
  "subscription_id": "00000000-0000-0000-0000-000000000000"
}
```

Example response:

```json
{
  "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a",
  "subscription_id": "00000000-0000-0000-0000-000000000000",
  "started_at": "2026-05-09T12:00:00+00:00",
  "completed_at": "2026-05-09T12:02:00+00:00",
  "total_findings": 1,
  "findings": [
    {
      "rule_id": "AZ-STOR-001",
      "rule_name": "Public Blob Access Enabled on Storage Account",
      "severity": "HIGH",
      "category": "Storage",
      "resource_id": "/subscriptions/example/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/example",
      "resource_name": "example",
      "resource_type": "Microsoft.Storage/storageAccounts",
      "description": "Storage accounts with public blob access enabled allow unauthenticated read access to blob data over the internet.",
      "remediation": "Disable public blob access on the storage account.",
      "playbook": "playbooks/cli/fix_az_stor_001.sh",
      "frameworks": {
        "CIS": "3.5",
        "NIST": "PR.AC-3",
        "ISO27001": "A.9.4.1"
      },
      "metadata": {},
      "detected_at": "2026-05-09T12:00:00+00:00",
      "scan_id": "6f4a08ac-7d3a-4d9a-a4b4-2a26e5f63c8a"
    }
  ]
}
```

Missing subscription response:

```json
{
  "error": "subscription_id is required"
}
```

---

## GET /api/score

Returns the overall security posture score from 0 to 100. The score starts at 100 and deducts 10 per HIGH finding, 5 per MEDIUM finding, and 2 per LOW finding.

Query parameters: none

Example response:

```json
{
  "score": 82,
  "max_score": 100
}
```

---

## GET /api/compliance/&lt;framework&gt;

Returns a pass/fail control breakdown for a supported compliance framework.

Supported frameworks:

| Path value | Framework file |
|---|---|
| `cis` | `cis_azure_benchmark.json` |
| `nist` | `nist_csf.json` |
| `iso27001` | `iso27001.json` |
| `soc2` | `soc2.json` |

Query parameters: none

Example response:

```json
{
  "framework": "CIS Microsoft Azure Foundations Benchmark",
  "version": "2.0.0",
  "total_controls": 20,
  "passed": 19,
  "failed": 1,
  "score_percent": 95,
  "controls": [
    {
      "rule_id": "AZ-STOR-001",
      "control_id": "3.5",
      "control_name": "Ensure that 'Public access level' is set to Private for blob containers",
      "status": "FAIL"
    }
  ]
}
```

Unknown framework response:

```json
{
  "error": "Unknown framework 'pci'",
  "supported": ["cis", "nist", "iso27001", "soc2"]
}
```
