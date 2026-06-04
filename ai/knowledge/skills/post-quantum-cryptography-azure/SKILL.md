---
name: post-quantum-cryptography-azure
description: Identifies and remediates non-quantum-safe cryptographic configurations in Azure including classical TLS key exchange, RSA and ECC keys in Key Vault, and classical certificate algorithms. Maps findings to NIST PQC standards FIPS 203, FIPS 204, and FIPS 205. Use when assessing quantum readiness of Azure infrastructure or building a Cryptographic Bill of Materials.
domain: cybersecurity
subdomain: post-quantum-cryptography
tags:
- post-quantum
- pqc
- azure
- key-vault
- tls
- cryptography
- cbom
version: '1.0'
author: openshield
license: Apache-2.0
nist_csf:
- PR.DS-2
- PR.DS-1
---

# Post-Quantum Cryptography Assessment for Azure

## When to Use
- When assessing an Azure environment for quantum readiness
- When building a Cryptographic Bill of Materials for Azure resources
- When identifying classical cryptographic algorithms that need migration
- When planning post-quantum migration for Key Vault keys and certificates
- When evaluating TLS configurations for quantum vulnerability

## Key Concepts

| Term | Definition |
|------|------------|
| Harvest Now Decrypt Later | Attack where adversaries collect encrypted traffic today and decrypt it when quantum computers become available |
| Shor's Algorithm | Quantum algorithm that can break RSA and ECC by solving integer factorisation and discrete logarithm problems efficiently |
| ML-KEM | Module Lattice Key Encapsulation Mechanism, NIST FIPS 203, post-quantum safe key exchange |
| ML-DSA | Module Lattice Digital Signature Algorithm, NIST FIPS 204, post-quantum safe signing |
| SLH-DSA | Stateless Hash-Based Digital Signature Algorithm, NIST FIPS 205, post-quantum safe signing |
| CBOM | Cryptographic Bill of Materials, inventory of all cryptographic assets in a system |
| PQMA | Post-Quantum Migration Analyser, tool for validating PQC migration paths |

## OpenShield PQC Rules

| Rule | Description | Severity |
|------|-------------|----------|
| AZ-PQC-001 | TLS below 1.3 on App Service | HIGH |
| AZ-PQC-002 | Key Vault key using RSA or ECC algorithm | HIGH |
| AZ-PQC-003 | Key Vault certificate using non-quantum-safe signature algorithm | MEDIUM |

## Assessment Workflow

### Step 1: Identify Classical Keys in Key Vault
```bash
az keyvault list --output table
az keyvault key list --vault-name <vault-name> --output table
az keyvault certificate list --vault-name <vault-name> --output table
```

### Step 2: Check TLS Configuration on App Services
```bash
az webapp list --output table
az webapp config show --resource-group <rg> --name <app-name> --query minTlsVersion
```

### Step 3: Build Cryptographic Bill of Materials
Document all findings with resource ID, algorithm type, key size, expiry date, and dependent services.

### Step 4: Prioritise Migration
1. Keys and certificates exposed to internet traffic first
2. Long-lived keys with high blast radius second
3. Internal service-to-service encryption third

## NIST PQC Standards Reference

| Standard | Algorithm | Use Case |
|----------|-----------|----------|
| FIPS 203 | ML-KEM | Key encapsulation, replacing RSA and ECDH key exchange |
| FIPS 204 | ML-DSA | Digital signatures, replacing RSA-PSS and ECDSA |
| FIPS 205 | SLH-DSA | Digital signatures, hash-based alternative |

## Compliance Mapping

| Framework | Control | Requirement |
|-----------|---------|-------------|
| NIST CSF | PR.DS-2 | Data in transit is protected using quantum-safe algorithms |
| ISO 27001 | A.10.1.1 | Cryptographic controls policy must address quantum threats |
| CIS Azure | 8.1 | Key management must include post-quantum migration planning |
| SOC 2 | CC6.7 | Encryption protecting data in transit must be quantum-safe |
