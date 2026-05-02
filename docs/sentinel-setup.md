# Sentinel Integration Setup Guide

## Prerequisites
- Azure account (free trial at azure.microsoft.com/free)
- Python 3.9+
- Azure CLI installed

## Part 1 - Create Log Analytics Workspace

az group create --name openshield-rg --location uksouth

az monitor log-analytics workspace create --resource-group openshield-rg --workspace-name openshield-laws --location uksouth --retention-time 30

Get Workspace ID:
az monitor log-analytics workspace show --resource-group openshield-rg --workspace-name openshield-laws --query customerId --output tsv

Get Shared Key:
az monitor log-analytics workspace get-shared-keys --resource-group openshield-rg --workspace-name openshield-laws --query primarySharedKey --output tsv

## Part 2 - Activate Sentinel

az extension add --name sentinel

az sentinel onboarding-state create --resource-group openshield-rg --workspace-name openshield-laws --name default

## Part 3 - Set Environment Variables

export SENTINEL_WORKSPACE_ID="your-workspace-id"
export SENTINEL_SHARED_KEY="your-shared-key"
export SENTINEL_LOG_TYPE="OpenShieldFindings"
export AZURE_SUBSCRIPTION_ID="your-subscription-id"
export AZURE_TENANT_ID="your-tenant-id"
export AZURE_CLIENT_ID="your-client-id"
export AZURE_CLIENT_SECRET="your-client-secret"

## Part 4 - Run Ingestion

Install dependencies:
pip install requests

Generate test findings:
python3 sentinel/tests/generate_test_findings.py

Push findings to Sentinel:
python3 sentinel/ingest.py scanner/output/test_findings.json scan-001

## Part 5 - Verify in Sentinel Logs

Run this query in Log Analytics:
OpenShieldFindings_CL | take 10

If you see rows the ingestion is working correctly.

## Part 6 - Deploy KQL Rules in Sentinel Analytics

Go to Microsoft Sentinel or Microsoft Defender XDR and navigate to Analytics. Create a Scheduled query rule for each file in sentinel/rules/

high_severity_finding.kql - Severity High - Run every 1 hour
misconfiguration_wave.kql - Severity High - Run every 2 hours
persistent_misconfiguration.kql - Severity Medium - Run every 24 hours
new_resource_type_critical.kql - Severity Critical - Run every 1 hour

Set alert threshold to greater than 0 for all rules.

## Part 7 - Verify Incidents

Go to Incidents in Sentinel or Microsoft Defender XDR. Within a few hours of deploying the rules you should see OpenShield incidents appearing automatically.
