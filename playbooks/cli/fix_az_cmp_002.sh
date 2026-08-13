#!/bin/bash
# OpenShield Remediation Playbook
# Rule: AZ-CMP-002 — Virtual machine disk not protected by CMK or ADE
# Usage: ./fix_az_cmp_002.sh <resource-group> <vm-name> <keyvault-name>
# Severity: HIGH
#
# This script only remediates a *confirmed* finding (metadata.determination
# == "non_compliant" — a disk resolved to Disk.encryption.type ==
# EncryptionAtRestWithPlatformKey with no ADE enabled). If the finding's
# metadata.determination is "indeterminate", the scanning principal could
# not read the Disk resource (missing Microsoft.Compute/disks/read, or the
# disk was deleted) and the actual encryption state is unknown. Running this
# script against an indeterminate finding may enable ADE on a disk that was
# already compliant via CMK. Run `az disk show --ids <disk-id>` to confirm
# the encryption state before proceeding in that case.

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
  echo "  3. If the finding was indeterminate, confirm the actual encryption"
  echo "     state with 'az disk show' before running this script."
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
