# Azure Vulnerable Scenario Plan

This document defines low-cost vulnerable Azure scenarios for manual
OpenShield validation. These scenarios are not CI automation. Do not run them
against production subscriptions.

All test execution results are `Pending`.

## General Requirements

- Use a dedicated test subscription or isolated student subscription.
- Use a dedicated resource group for each validation run.
- Do not add real subscription IDs, tenant IDs, client IDs, secrets, or
  resource names to the repository.
- Prefer Azure CLI commands that create only low-cost resources.
- Do not create virtual machines, VPN gateways, Azure Firewall, Application
  Gateway, or other expensive resources in Phase 1.
- Clean up the validation resource group after each run.

## Naming And Tagging

Use placeholders in documentation and replace them locally during execution.

```bash
export OSHIELD_LOCATION="<azure-region>"
export OSHIELD_RG="<validation-resource-group>"
export OSHIELD_SUFFIX="<short-lowercase-alphanumeric-suffix>"
export OSHIELD_DELETE_AFTER="<yyyy-mm-dd>"
```

Recommended tags:

```bash
--tags purpose=openshield-validation owner=contributor delete-after="$OSHIELD_DELETE_AFTER"
```

Resource group creation:

```bash
az group create \
  --name "$OSHIELD_RG" \
  --location "$OSHIELD_LOCATION" \
  --tags purpose=openshield-validation owner=contributor delete-after="$OSHIELD_DELETE_AFTER"
```

## Validation Scan Step

Run the scanner after creating the vulnerable resource:

```bash
python -c "
from dotenv import load_dotenv; load_dotenv()
import json, os
from scanner.engine import ScanEngine

result = ScanEngine(os.environ['AZURE_SUBSCRIPTION_ID']).run_scan()
print(json.dumps(result, indent=2))
"
```

Record only non-secret evidence in `docs/validation/TEST_RESULTS.md`.

## Cleanup Strategy

Primary cleanup should delete the validation resource group:

```bash
az group delete --name "$OSHIELD_RG" --yes --no-wait
```

Before cleanup, verify that the resource group contains only validation
resources:

```bash
az resource list --resource-group "$OSHIELD_RG" --output table
```

For Key Vault scenarios, remember that soft-deleted vault names may remain
reserved for the retention period. Purge only the explicitly created
validation vault, only if permitted, and only if purge protection was not
enabled.

## Scenario Matrix

| Test ID | Azure Service | Resource Group | Vulnerable Resource | Misconfiguration Introduced | Expected OpenShield Finding | Validation Command Or Scan Step | Expected Result | Actual Result | Pass/Fail | Cleanup Command |
|---|---|---|---|---|---|---|---|---|---|---|
| `VAL-STOR-001` | Storage Account | `$OSHIELD_RG` | Storage account named with `$OSHIELD_SUFFIX` | Blob public access enabled on the storage account | `AZ-STOR-001` on `Microsoft.Storage/storageAccounts` | Run `ScanEngine(...).run_scan()` and filter findings for `AZ-STOR-001` | Finding includes the validation storage account name and severity `HIGH` | Pending | Pending | `az group delete --name "$OSHIELD_RG" --yes --no-wait` |
| `VAL-NET-001` | Network Security Group | `$OSHIELD_RG` | NSG named with `$OSHIELD_SUFFIX` | Inbound allow rule for TCP `22` from internet | `AZ-NET-001` on `Microsoft.Network/networkSecurityGroups` | Run `ScanEngine(...).run_scan()` and filter findings for `AZ-NET-001` | Finding includes the validation NSG name and severity `HIGH` | Pending | Pending | `az group delete --name "$OSHIELD_RG" --yes --no-wait` |
| `VAL-NET-002` | Network Security Group | `$OSHIELD_RG` | NSG named with `$OSHIELD_SUFFIX` | Inbound allow rule for TCP `3389` from internet | `AZ-NET-002` on `Microsoft.Network/networkSecurityGroups` | Run `ScanEngine(...).run_scan()` and filter findings for `AZ-NET-002` | Finding includes the validation NSG name and severity `HIGH` | Pending | Pending | `az group delete --name "$OSHIELD_RG" --yes --no-wait` |
| `VAL-KV-002` | Key Vault | `$OSHIELD_RG` | Key Vault named with `$OSHIELD_SUFFIX` | Public network access enabled without a private endpoint | `AZ-KV-002` on `Microsoft.KeyVault/vaults` | Run `ScanEngine(...).run_scan()` and filter findings for `AZ-KV-002` | Finding includes the validation Key Vault name and severity `HIGH` | Pending | Pending | `az group delete --name "$OSHIELD_RG" --yes --no-wait` |
| `VAL-KV-004` | Key Vault | `$OSHIELD_RG` | Key Vault named with `$OSHIELD_SUFFIX` | Purge protection disabled | `AZ-KV-004` on `Microsoft.KeyVault/vaults` | Run `ScanEngine(...).run_scan()` and filter findings for `AZ-KV-004` | Finding includes the validation Key Vault name and severity `MEDIUM` | Pending | Pending | `az group delete --name "$OSHIELD_RG" --yes --no-wait` |

## Scenario Details

### VAL-STOR-001: Storage Account Public Blob Access

Azure service: Storage Account

Resource group: `$OSHIELD_RG`

Vulnerable resource to create: one low-cost general purpose v2 storage account
with a globally unique name.

Misconfiguration introduced: public blob access enabled at the account level.

Expected OpenShield rule/finding: `AZ-STOR-001`.

Example setup:

```bash
az storage account create \
  --name "oshieldstor$OSHIELD_SUFFIX" \
  --resource-group "$OSHIELD_RG" \
  --location "$OSHIELD_LOCATION" \
  --sku Standard_LRS \
  --kind StorageV2 \
  --allow-blob-public-access true \
  --tags purpose=openshield-validation owner=contributor delete-after="$OSHIELD_DELETE_AFTER"
```

Validation command or scan step: run `ScanEngine(...).run_scan()` and search
the JSON output for `AZ-STOR-001`.

Expected result: a `HIGH` severity finding for the validation storage account.

Actual result: Pending

Pass/fail: Pending

Cleanup command:

```bash
az group delete --name "$OSHIELD_RG" --yes --no-wait
```

### VAL-NET-001: NSG Allowing SSH From Internet

Azure service: Network Security Group

Resource group: `$OSHIELD_RG`

Vulnerable resource to create: one NSG.

Misconfiguration introduced: inbound allow rule for TCP port `22` from
`0.0.0.0/0`.

Expected OpenShield rule/finding: `AZ-NET-001`.

Example setup:

```bash
az network nsg create \
  --name "oshield-nsg-ssh-$OSHIELD_SUFFIX" \
  --resource-group "$OSHIELD_RG" \
  --location "$OSHIELD_LOCATION" \
  --tags purpose=openshield-validation owner=contributor delete-after="$OSHIELD_DELETE_AFTER"

az network nsg rule create \
  --resource-group "$OSHIELD_RG" \
  --nsg-name "oshield-nsg-ssh-$OSHIELD_SUFFIX" \
  --name "AllowSSHFromInternet" \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes 0.0.0.0/0 \
  --source-port-ranges "*" \
  --destination-address-prefixes "*" \
  --destination-port-ranges 22
```

Validation command or scan step: run `ScanEngine(...).run_scan()` and search
the JSON output for `AZ-NET-001`.

Expected result: a `HIGH` severity finding for the validation NSG.

Actual result: Pending

Pass/fail: Pending

Cleanup command:

```bash
az group delete --name "$OSHIELD_RG" --yes --no-wait
```

### VAL-NET-002: NSG Allowing RDP From Internet

Azure service: Network Security Group

Resource group: `$OSHIELD_RG`

Vulnerable resource to create: one NSG.

Misconfiguration introduced: inbound allow rule for TCP port `3389` from
`0.0.0.0/0`.

Expected OpenShield rule/finding: `AZ-NET-002`.

Example setup:

```bash
az network nsg create \
  --name "oshield-nsg-rdp-$OSHIELD_SUFFIX" \
  --resource-group "$OSHIELD_RG" \
  --location "$OSHIELD_LOCATION" \
  --tags purpose=openshield-validation owner=contributor delete-after="$OSHIELD_DELETE_AFTER"

az network nsg rule create \
  --resource-group "$OSHIELD_RG" \
  --nsg-name "oshield-nsg-rdp-$OSHIELD_SUFFIX" \
  --name "AllowRDPFromInternet" \
  --priority 100 \
  --direction Inbound \
  --access Allow \
  --protocol Tcp \
  --source-address-prefixes 0.0.0.0/0 \
  --source-port-ranges "*" \
  --destination-address-prefixes "*" \
  --destination-port-ranges 3389
```

Validation command or scan step: run `ScanEngine(...).run_scan()` and search
the JSON output for `AZ-NET-002`.

Expected result: a `HIGH` severity finding for the validation NSG.

Actual result: Pending

Pass/fail: Pending

Cleanup command:

```bash
az group delete --name "$OSHIELD_RG" --yes --no-wait
```

### VAL-KV-002: Key Vault Public Network Access

Azure service: Key Vault

Resource group: `$OSHIELD_RG`

Vulnerable resource to create: one Key Vault with a globally unique name.

Misconfiguration introduced: public network access enabled without a private
endpoint.

Expected OpenShield rule/finding: `AZ-KV-002`.

Example setup:

```bash
az keyvault create \
  --name "oshield-kv-$OSHIELD_SUFFIX" \
  --resource-group "$OSHIELD_RG" \
  --location "$OSHIELD_LOCATION" \
  --public-network-access Enabled \
  --enable-purge-protection false \
  --tags purpose=openshield-validation owner=contributor delete-after="$OSHIELD_DELETE_AFTER"
```

Validation command or scan step: run `ScanEngine(...).run_scan()` and search
the JSON output for `AZ-KV-002`.

Expected result: a `HIGH` severity finding for the validation Key Vault.

Actual result: Pending

Pass/fail: Pending

Cleanup command:

```bash
az group delete --name "$OSHIELD_RG" --yes --no-wait
```

### VAL-KV-004: Key Vault Purge Protection Disabled

Azure service: Key Vault

Resource group: `$OSHIELD_RG`

Vulnerable resource to create: one Key Vault with purge protection disabled.

Misconfiguration introduced: purge protection disabled.

Expected OpenShield rule/finding: `AZ-KV-004`.

Example setup:

```bash
az keyvault create \
  --name "oshield-kv-purge-$OSHIELD_SUFFIX" \
  --resource-group "$OSHIELD_RG" \
  --location "$OSHIELD_LOCATION" \
  --enable-purge-protection false \
  --tags purpose=openshield-validation owner=contributor delete-after="$OSHIELD_DELETE_AFTER"
```

Validation command or scan step: run `ScanEngine(...).run_scan()` and search
the JSON output for `AZ-KV-004`.

Expected result: a `MEDIUM` severity finding for the validation Key Vault.

Actual result: Pending

Pass/fail: Pending

Cleanup command:

```bash
az group delete --name "$OSHIELD_RG" --yes --no-wait
```

## Known Risks

### Azure Student Subscription Limits

Student subscriptions have limited credit and quotas. Avoid resources that
consume compute, gateway, firewall, or premium capacity during initial
validation.

### Resource Naming Uniqueness

Storage account and Key Vault names are globally unique. Use a short local
suffix and do not commit the final names.

### Cleanup Failures

Resource group deletion can fail or take time. Always inspect the resource
group before and after cleanup.

### Tenant-Level Permissions

Identity rules may require tenant-wide permissions or Microsoft Graph access.
Do not test those rules in a shared tenant without explicit approval.

### Unsafe Or Impractical Rules

Rules that require VMs, VPN gateways, Azure Firewall, Application Gateway, SQL
servers, or production-like identity settings should be deferred until a
maintainer approves the scenario and cost.

### False Positives And False Negatives

Record unexpected findings as `Pending investigation`. Do not remove evidence
or mark a test as passed when the expected rule did not appear.
