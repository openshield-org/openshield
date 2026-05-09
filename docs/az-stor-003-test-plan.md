# Test Plan — AZ-STOR-003
# Storage Account Has No Lifecycle Management Policy
# ============================================================

## 1. Overview

This test plan covers verification of the AZ-STOR-003 scanner rule
and its remediation playbook. The goal is to confirm:

- The rule correctly identifies non-compliant storage accounts
- The rule correctly ignores compliant storage accounts
- The playbook successfully creates a lifecycle policy
- The rule finds zero issues after the playbook runs

---

## 2. Files Under Test

| File | Purpose |
|---|---|
| scanner/rules/az_stor_003.py | Scanner rule |
| playbooks/cli/fix_az_stor_003.sh | Remediation script |
| scanner/azure_client.py | New method: get_storage_lifecycle_policy() |
| compliance/frameworks/cis_azure_benchmark.json | CIS mapping |
| compliance/frameworks/nist_csf.json | NIST mapping |
| compliance/frameworks/iso27001.json | ISO 27001 mapping |
| compliance/frameworks/soc2.json | SOC 2 mapping |

---

## 3. Test Environment Setup

### 3.1 Prerequisites

- Python 3.10+
- Azure free trial account (portal.azure.com)
- Azure CLI installed and logged in (az login)
- OpenShield repo cloned and dependencies installed (pip install -r requirements.txt)
- .env file populated with AZURE_SUBSCRIPTION_ID, AZURE_CLIENT_ID,
  AZURE_CLIENT_SECRET, AZURE_TENANT_ID
- StorageV2 accounts used for all tests

### 3.2 Create Test Resources in Azure

Run these commands once before testing. They create two storage accounts:
one without a lifecycle policy (should be flagged) and one with a policy
(should NOT be flagged).

    # Create resource group
    az group create --name openshield-test-rg --location eastus

    # Storage account WITHOUT lifecycle policy (will be flagged)
    az storage account create \
      --name oshieldtestnopolicy \
      --resource-group openshield-test-rg \
      --sku Standard_LRS \
      --location eastus

    # Storage account WITH lifecycle policy (will NOT be flagged)
    az storage account create \
      --name oshieldtestpolicyon \
      --resource-group openshield-test-rg \
      --sku Standard_LRS \
      --location eastus

    # Manually apply a policy to the second account
    az storage account management-policy create \
      --account-name oshieldtestpolicyon \
      --resource-group openshield-test-rg \
      --policy '{
        "rules": [{
          "name": "test-policy",
          "enabled": true,
          "type": "Lifecycle",
          "definition": {
            "filters": {"blobTypes": ["blockBlob"]},
            "actions": {
              "baseBlob": {
                "delete": {"daysAfterLastAccessTimeGreaterThan": 365}
              }
            }
          }
        }]
      }'

---

## 4. Test Cases

---

### TC-001 — Rule detects non-compliant account (POSITIVE TEST)

**Purpose:** Confirm the rule flags a storage account with no lifecycle policy.

**Pre-condition:** oshieldtestnopolicy exists with no lifecycle policy.

**Steps:**

    python -c "
    from dotenv import load_dotenv; load_dotenv()
    import os
    from scanner.azure_client import AzureClient
    from scanner.rules import az_stor_003 as rule

    client = AzureClient(os.environ['AZURE_SUBSCRIPTION_ID'])
    findings = rule.scan(client, os.environ['AZURE_SUBSCRIPTION_ID'])
    print(f'Total findings: {len(findings)}')
    for f in findings:
        print(f'  [{f[\"severity\"]}] {f[\"resource_name\"]}')
    "

**Expected result:**
- At minimum one finding returned
- oshieldtestnopolicy appears in the findings list
- Finding has severity = MEDIUM
- Finding has rule_id = AZ-STOR-003
- Finding dict contains all required keys:
  rule_id, rule_name, severity, category, resource_id, resource_name,
  resource_type, description, remediation, playbook, frameworks

**Pass criteria:** oshieldtestnopolicy is in findings list.

---

### TC-002 — Rule ignores compliant account (NEGATIVE TEST)

**Purpose:** Confirm the rule does NOT flag accounts that already have a policy.

**Pre-condition:** oshieldtestpolicyon exists WITH a lifecycle policy applied.

**Steps:** Same script as TC-001. Inspect the findings list.

**Expected result:**
- oshieldtestpolicyon does NOT appear in the findings list.

**Pass criteria:** oshieldtestpolicyon absent from findings.

---

### TC-003 — Finding dict has correct structure

**Purpose:** Confirm every required field is present and correctly typed.

**Steps:**

    python -c "
    from dotenv import load_dotenv; load_dotenv()
    import os, json
    from scanner.azure_client import AzureClient
    from scanner.rules import az_stor_003 as rule

    REQUIRED_KEYS = [
        'rule_id', 'rule_name', 'severity', 'category',
        'resource_id', 'resource_name', 'resource_type',
        'description', 'remediation', 'playbook', 'frameworks'
    ]

    client = AzureClient(os.environ['AZURE_SUBSCRIPTION_ID'])
    findings = rule.scan(client, os.environ['AZURE_SUBSCRIPTION_ID'])

    for f in findings:
        missing = [k for k in REQUIRED_KEYS if k not in f]
        if missing:
            print(f'FAIL — missing keys: {missing}')
        else:
            print(f'PASS — {f[\"resource_name\"]} has all required keys')
        print(f'  frameworks: {f[\"frameworks\"]}')
        print(f'  severity: {f[\"severity\"]}')
    "

**Expected result:**
- No missing keys reported
- severity = MEDIUM
- frameworks dict contains CIS, NIST, ISO27001 keys

**Pass criteria:** All required keys present in every finding.

---

### TC-004 — Full scan engine picks up the rule

**Purpose:** Confirm the rule loads automatically when the engine runs —
no manual registration needed.

**Steps:**

    python -c "
    from dotenv import load_dotenv; load_dotenv()
    import json, os
    from scanner.engine import ScanEngine

    engine = ScanEngine(os.environ['AZURE_SUBSCRIPTION_ID'])
    rule_ids = [getattr(r, 'RULE_ID', 'UNKNOWN') for r in engine.rules]
    print('Loaded rules:', rule_ids)
    print('AZ-STOR-003 loaded:', 'AZ-STOR-003' in rule_ids)
    "

**Expected result:**
- AZ-STOR-003 appears in the loaded rules list.

**Pass criteria:** 'AZ-STOR-003 loaded: True' in output.

---

### TC-005 — Playbook prints usage when called with no arguments

**Purpose:** Confirm the script does not crash silently and has clear usage.

**Steps:**

    bash playbooks/cli/fix_az_stor_003.sh

**Expected result:**
- Prints usage instructions
- Exits with a non-zero exit code (1)
- Does NOT make any changes to Azure

**Pass criteria:** Usage text displayed, script exits cleanly.

---

### TC-006 — Playbook remediates the non-compliant account

**Purpose:** Confirm the playbook successfully creates a lifecycle policy.

**Pre-condition:** oshieldtestnopolicy has no lifecycle policy.

**Steps:**

    bash playbooks/cli/fix_az_stor_003.sh \
      openshield-test-rg \
      oshieldtestnopolicy \
      365

    # Verify the policy was created
    az storage account management-policy show \
      --account-name oshieldtestnopolicy \
      --resource-group openshield-test-rg

**Expected result:**
- Script prints confirmation message
- az management-policy show returns a JSON policy object
- Policy contains a rule named openshield-lifecycle-rule
- Policy shows tierToCool at 30 days, tierToArchive at 90 days,
  delete at 365 days

**Pass criteria:** Policy visible in Azure portal and via CLI show command.

---

### TC-007 — Rule returns zero findings after remediation

**Purpose:** Full end-to-end — confirm the rule clears after the fix is applied.

**Pre-condition:** TC-006 has run successfully (oshieldtestnopolicy now has a policy).

**Steps:** Re-run TC-001 script.

**Expected result:**
- oshieldtestnopolicy no longer appears in findings.

**Pass criteria:** Previously flagged account no longer in findings list.

---

### TC-008 — Script handles non-existent account gracefully

**Purpose:** Confirm the script fails cleanly when given a valid-format name
that does not exist in Azure — the failure comes from the Azure CLI, not
from our validation.

**Steps:**

    bash playbooks/cli/fix_az_stor_003.sh \
      openshield-test-rg \
      oshieldaccountxyz999 \
      365

    # When prompted, enter "y" to proceed past the confirmation.

**Expected result:**
- Passes all input validation (name format is valid)
- Azure CLI returns a ResourceNotFound error
- Script exits with a non-zero exit code from set -euo pipefail
- Error from Azure CLI is visible in output

**Pass criteria:** Script exits with Azure error, does not silently continue.

---

### TC-009 — Playbook rejects invalid days-to-delete value

**Purpose:** Confirm integer validation works — prevents broken JSON policy.

**Steps:**

    bash playbooks/cli/fix_az_stor_003.sh \
      openshield-test-rg \
      oshieldtestnopolicy \
      "not-a-number"

**Expected result:**
- Prints: `ERROR: days-to-delete must be a positive integer`
- Exits with code 1
- Makes no changes to Azure

**Pass criteria:** Error message displayed, exit code 1.

---

### TC-010 — Playbook rejects shell-unsafe characters in arguments

**Purpose:** Confirm input sanitisation prevents shell injection.

**Steps:**

    bash playbooks/cli/fix_az_stor_003.sh \
      "my-rg; echo INJECTED" \
      oshieldtestnopolicy

**Expected result:**
- Prints: `ERROR: resource-group contains invalid characters`
- Exits with code 1
- The string "INJECTED" does NOT appear in output

**Pass criteria:** Error shown, no command injection executed.

---

### TC-011 — Playbook enables last access tracking before applying policy

**Purpose:** Confirm the prerequisite step runs before the policy is created.
Without last access tracking enabled, `daysAfterLastAccessTimeGreaterThan`
policies are accepted by Azure but never fire — a silent failure.

**Steps:**

    # Confirm tracking is OFF before the test
    az storage account blob-service-properties show \
      --account-name oshieldtestnopolicy \
      --resource-group openshield-test-rg \
      --query "lastAccessTimeTrackingPolicy.enable"
    # Should return: null or false

    # Run the playbook (enter "y" when prompted)
    bash playbooks/cli/fix_az_stor_003.sh \
      openshield-test-rg \
      oshieldtestnopolicy \
      365

    # Confirm tracking is now ON
    az storage account blob-service-properties show \
      --account-name oshieldtestnopolicy \
      --resource-group openshield-test-rg \
      --query "lastAccessTimeTrackingPolicy.enable"
    # Must return: true

**Expected result:**
- Before playbook: tracking disabled or null
- After playbook: tracking enabled = true
- Policy also present (verify with management-policy show)

**Pass criteria:** `lastAccessTimeTrackingPolicy.enable` is `true` after the
playbook runs.

---

## 5. Cleanup

After all tests pass, delete the test resources to avoid charges:

    az group delete --name openshield-test-rg --yes --no-wait

---

## 6. Pass / Fail Summary Table

| Test Case | Description | Expected | Status |
|---|---|---|---|
| TC-001 | Rule detects non-compliant account | Finding returned | [ ] |
| TC-002 | Rule ignores compliant account | No finding | [ ] |
| TC-003 | Finding dict structure | All required keys present | [ ] |
| TC-004 | Engine loads rule automatically | AZ-STOR-003 in loaded list | [ ] |
| TC-005 | Playbook prints usage on no args | Usage text + exit 1 | [ ] |
| TC-006 | Playbook creates lifecycle policy | Policy visible in Azure | [ ] |
| TC-007 | Rule clears after remediation | Zero findings post-fix | [ ] |
| TC-008 | Script handles non-existent account | Exits with Azure error | [ ] |
| TC-009 | Playbook rejects non-integer days | Error + exit 1 | [ ] |
| TC-010 | Playbook rejects unsafe characters | Error, no injection | [ ] |
| TC-011 | Playbook enables last access tracking | Tracking = true after run | [ ] |

All 11 test cases must pass before opening the PR.
