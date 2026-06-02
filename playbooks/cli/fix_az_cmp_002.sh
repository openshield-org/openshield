#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-CMP-002 — Virtual machine disk not protected by CMK or ADE
# Usage: ./fix_az_cmp_002.sh <resource-group> <vm-name> <keyvault-name>
# Severity: HIGH

set -e

RESOURCE_GROUP=$1
VM_NAME=$2
KEYVAULT_NAME=$3

if [ -z "$RESOURCE_GROUP" ] || [ -z "$VM_NAME" ] || [ -z "$KEYVAULT_NAME" ]; then
  echo "Usage: $0 <resource-group> <vm-name> <keyvault-name>"
  echo ""
  echo "Prerequisites:"
  echo "  1. Create a Key Vault if one does not exist:"
  echo "     az keyvault create --resource-group <rg> --name <kv-name> --enabled-for-disk-encryption true"
  echo "  2. Ensure the VM is running before enabling encryption"
  exit 1
fi

echo "Enabling Azure Disk Encryption on VM '$VM_NAME'..."

az vm encryption enable \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME" \
  --disk-encryption-keyvault "$KEYVAULT_NAME" \
  --volume-type All

echo "Waiting for encryption to complete..."

az vm encryption show \
  --resource-group "$RESOURCE_GROUP" \
  --name "$VM_NAME"

echo "Disk encryption enabled on all volumes for VM '$VM_NAME'."
echo "The VM may restart during the encryption process."
echo "Encryption of large disks can take several hours to complete."
