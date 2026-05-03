# Adding a New Scan Rule

This is the fastest way to contribute to OpenShield. You can write, test, and submit a new rule in under 30 minutes.

---

## The Rule Template

Create a new file in `scanner/rules/`. The filename should match your rule ID in lowercase with underscores:

```
scanner/rules/az_stor_001.py  ← for rule AZ-STOR-001
```

Every rule file must have this exact structure:

```python
"""AZ-XXXX-000: One-line description of what this rule detects."""

from typing import Any, Dict, List

# ── Required module-level constants ─────────────────────────────────────────

RULE_ID = "AZ-XXXX-000"          # Unique ID. Check existing rules to avoid clashes.
RULE_NAME = "Human-readable name" # Shown in the dashboard and reports.
SEVERITY = "HIGH"                 # HIGH | MEDIUM | LOW | INFO
CATEGORY = "Storage"              # Storage | Network | Identity | Database | Compute | KeyVault
FRAMEWORKS = {
    "CIS":      "3.5",            # CIS Azure Benchmark control ID
    "NIST":     "PR.AC-3",        # NIST CSF subcategory
    "ISO27001": "A.9.4.1",        # ISO 27001 Annex A control
}
DESCRIPTION = (
    "Explain WHY this is a security risk. One or two sentences. "
    "What can an attacker do if this misconfiguration exists?"
)
REMEDIATION = (
    "Explain HOW to fix it. What setting to change, or what command to run."
)
PLAYBOOK = "playbooks/cli/fix_az_xxxx_000.sh"  # path to the matching fix script


# ── Required scan function ───────────────────────────────────────────────────

def scan(azure_client: Any, subscription_id: str) -> List[Dict[str, Any]]:
    """Return a list of findings. Return [] if no issues are found.

    Args:
        azure_client:    An AzureClient instance with all SDK clients pre-configured.
        subscription_id: The Azure subscription ID being scanned.

    Returns:
        A list of finding dicts. Each dict must contain the keys below.
    """
    findings: List[Dict[str, Any]] = []

    for resource in azure_client.get_storage_accounts():  # ← replace with the right method
        if <condition_that_indicates_a_problem>:
            findings.append({
                "rule_id":       RULE_ID,
                "rule_name":     RULE_NAME,
                "severity":      SEVERITY,
                "category":      CATEGORY,
                "resource_id":   resource.id,
                "resource_name": resource.name,
                "resource_type": "Microsoft.Storage/storageAccounts",  # ← update
                "description":   DESCRIPTION,
                "remediation":   REMEDIATION,
                "playbook":      PLAYBOOK,
                "frameworks":    FRAMEWORKS,
            })

    return findings
```

---

## Field-by-Field Explanation

| Field | What to write |
|---|---|
| `RULE_ID` | `AZ-[CATEGORY]-[NUMBER]`. Prefix map: STOR, NET, IDN, DB, CMP, KV. Look at existing rules for the next number. |
| `SEVERITY` | `HIGH` = direct exploitation risk, `MEDIUM` = indirect or partial risk, `LOW` = best practice, `INFO` = informational only |
| `CATEGORY` | Matches the resource type being scanned |
| `FRAMEWORKS` | Use real control IDs from each framework. Refer to `compliance/frameworks/` JSON files for examples. |
| `DESCRIPTION` | Focus on WHY it matters — what is the real-world attack scenario? |
| `REMEDIATION` | Be specific. Name the Azure Portal setting or the exact CLI flag. |
| `PLAYBOOK` | Path to the matching bash script in `playbooks/cli/`. You must create this file too. |
| `resource_type` | The full Azure resource provider type string, e.g. `Microsoft.Network/networkSecurityGroups` |

---

## AzureClient Methods Available

| Method | Returns |
|---|---|
| `azure_client.get_storage_accounts()` | List of StorageAccount objects |
| `azure_client.get_network_security_groups()` | List of NetworkSecurityGroup objects |
| `azure_client.get_virtual_machines()` | List of VirtualMachine objects |
| `azure_client.get_postgresql_servers()` | List of Server objects (PostgreSQL single-server) |
| `azure_client.get_sql_servers()` | List of Server objects (Azure SQL) |
| `azure_client.get_sql_server_auditing_policy(rg, name)` | ServerBlobAuditingPolicy or None |
| `azure_client.get_key_vaults()` | List of Vault objects (with full properties) |
| `azure_client.get_service_principals()` | List of RoleAssignment objects for service principals |
| `azure_client.get_network_interface(rg, name)` | NetworkInterface or None |
| `azure_client.get_conditional_access_policies()` | List of CA policy dicts from MS Graph |
| `azure_client.parse_resource_id(id)` | Dict with `resource_group` and `name` |

All methods return an empty list on failure — your scan function never needs to handle SDK exceptions.

---

## Write the Remediation Playbook

Create a matching bash script in `playbooks/cli/`:

```bash
#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-XXXX-000 — Your Rule Name
# Usage: ./fix_az_xxxx_000.sh <resource-group> <resource-name>
# Severity: HIGH

set -e

RESOURCE_GROUP=$1
RESOURCE_NAME=$2

if [ -z "$RESOURCE_GROUP" ] || [ -z "$RESOURCE_NAME" ]; then
  echo "Usage: $0 <resource-group> <resource-name>"
  exit 1
fi

# The actual az CLI command to fix the issue
az <service> <resource-type> update \
  --resource-group "$RESOURCE_GROUP" \
  --name "$RESOURCE_NAME" \
  --<setting> <value>

echo "✅ Remediation complete for $RESOURCE_NAME"
```

---

## Test Your Rule Locally

```bash
# 1. Set credentials
cp .env.example .env
# Fill in your Azure credentials in .env

# 2. Load env and run your rule in isolation
python -c "
from dotenv import load_dotenv; load_dotenv()
import os
from scanner.azure_client import AzureClient
from scanner.rules import az_xxxx_000 as rule  # replace with your module name

client = AzureClient(os.environ['AZURE_SUBSCRIPTION_ID'])
findings = rule.scan(client, os.environ['AZURE_SUBSCRIPTION_ID'])
print(f'Found {len(findings)} issue(s):')
for f in findings:
    print(f'  [{f[\"severity\"]}] {f[\"resource_name\"]} — {f[\"rule_name\"]}')
"

# 3. Or run the full scan engine (loads all rules)
python -c "
from dotenv import load_dotenv; load_dotenv()
import json, os
from scanner.engine import ScanEngine
engine = ScanEngine(os.environ['AZURE_SUBSCRIPTION_ID'])
result = engine.run_scan()
print(json.dumps(result, indent=2))
"
```

---

## Update the Compliance Framework Files

If your rule maps to controls not yet in the compliance JSON files, add entries to the relevant file(s) in `compliance/frameworks/`:

```json
{
  "controls": {
    "AZ-XXXX-000": {
      "control_id": "3.7",
      "control_name": "CIS control name here",
      "description": "Why this control is relevant to your finding."
    }
  }
}
```

---

## Submit a Pull Request

```bash
git checkout -b rule/az-xxxx-000-short-description
git add scanner/rules/az_xxxx_000.py playbooks/cli/fix_az_xxxx_000.sh
git commit -m "feat: add rule AZ-XXXX-000 — short description"
git push origin rule/az-xxxx-000-short-description
```

Then open a PR. Use the PR template — it will ask you for the rule ID, severity, and which frameworks you mapped. A maintainer will review within 48 hours.

---

## Common Mistakes to Avoid

- **Rule ID clash**: always check `scanner/rules/` for existing IDs before numbering your rule.
- **Missing playbook**: every rule must have a matching `playbooks/cli/fix_*.sh` file.
- **Hardcoded subscription ID**: use the `subscription_id` parameter passed to `scan()`, never hardcode.
- **Exceptions crashing the scan**: the engine catches unhandled exceptions per rule, but write defensively — use `getattr(obj, "field", default)` for optional SDK attributes.
- **Empty `frameworks` dict**: always populate all three keys (CIS, NIST, ISO27001) even if you map to `"N/A"`.



## Real-world impact of each rule

**AZ-STOR-001 — Public blob access enabled**
This is how 38 million records leaked in the 2021 Power Apps breach — blob containers set to public, no authentication needed, just know the URL and download everything. Attackers don't even need to "hack" anything. Automated tools scan Azure for public blobs constantly. If yours is exposed it will be found, usually within hours.

**AZ-STOR-002 — Storage account allows unencrypted HTTP**
Any data moving over plain HTTP can be read by anyone on the same network path. This sounds theoretical until you realise most corporate VPNs, shared offices and cloud interconnects are exactly that kind of shared environment. One internal tool uploading customer data over HTTP to Azure storage is all it takes. The fix is one toggle — HTTPS only — but it gets missed constantly.

**AZ-NET-001 — NSG allows RDP from internet**
Port 3389 open to the world is basically putting a front door on your VM with a note saying "try your luck." Botnets scan the entire internet for open RDP ports continuously — your VM will be found within minutes of provisioning. The Colonial Pipeline ransomware attack in 2021 started exactly this way. One exposed RDP port, one weak password, game over.

**AZ-NET-002 — NSG allows SSH from internet**
SSH brute forcing never stops. There are always automated scripts hammering port 22 across the entire internet trying username and password combinations from leaked credential lists. A university cluster got owned this way in 2023 and was used for crypto mining for three months before anyone noticed. Lock SSH down to specific IPs or use Azure Bastion — there is no good reason for port 22 to be open to 0.0.0.0/0.

**AZ-IDN-001 — Overprivileged service principal**
Contributor at subscription scope means the service principal can touch everything — every VM, every database, every storage account across the whole subscription. The moment that client secret leaks — through a git commit, a build log, a misconfigured app — the attacker has the keys to the kingdom. This exact pattern showed up in the SolarWinds breach. Least privilege is not optional.

**AZ-IDN-002 — MFA not enforced on privileged accounts**
Credential stuffing is not sophisticated. Attackers just take leaked password lists from other breaches and try them on Azure AD. Without MFA a matching password is all they need. Microsoft says MFA stops 99.9% of these attacks. A Global Admin account without MFA is genuinely one of the highest risk findings you can have — one leaked password from any other service and your entire tenant is gone.

**AZ-DB-001 — SQL Server TDE disabled**
The database itself might be behind a firewall, but what about the backups? Backup files get moved around — to blob storage, to tapes, to DR sites. Without TDE the data is sitting in plain text in all of those places. A healthcare company learned this the hard way in 2019 when stolen backup files exposed 2.3 million patient records. The attacker never touched the live database.

**AZ-DB-002 — SQL Server firewall allows all IPs**
Opening the SQL Server firewall to all IPs is the same as putting your database on the public internet. Shodan and similar tools index these constantly. In 2020 a startup had their production database dumped within days of launching because the firewall rule was still set to 0.0.0.0 from a development config that nobody cleaned up. Lock it to your app service IPs only — nothing else needs direct database access.

**AZ-CMP-001 — Unencrypted managed disk**
An attacker who gets into your subscription — even temporarily — can snapshot a disk in seconds. They create the snapshot, export it, mount it on their own VM and read everything on it at their leisure. The original VM keeps running, no one notices. A SaaS company found out about this 6 weeks after it happened when their data showed up for sale. The disks were unencrypted so the snapshot was immediately readable.

**AZ-KV-001 — Key Vault soft delete disabled**
Key Vault is where everything important lives — database passwords, API keys, TLS certificates, encryption keys. Without soft delete an attacker or a disgruntled employee can delete every single secret permanently in about 30 seconds. No recovery, no rollback. A real incident in 2021 saw an employee delete an entire production Key Vault on their last day. The company was down for 6 days rebuilding access from scratch. Soft delete costs nothing to enable.
