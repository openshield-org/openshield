# OpenShield

> **Open source Cloud Security Posture Management (CSPM) for Azure - detect misconfigurations, map to CIS/NIST/ISO27001/SOC2, fix them with one command, and identify cryptographic assets requiring quantum-safe migration.**

[![GitHub Repo stars](https://img.shields.io/github/stars/openshield-org/openshield?style=flat-square)](https://github.com/openshield-org/openshield/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/openshield-org/openshield?style=flat-square)](https://github.com/openshield-org/openshield/network/members)
[![GitHub contributors](https://img.shields.io/github/contributors/openshield-org/openshield?style=flat-square)](https://github.com/openshield-org/openshield/graphs/contributors)
[![GitHub last commit](https://img.shields.io/github/last-commit/openshield-org/openshield?style=flat-square)](https://github.com/openshield-org/openshield/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/openshield-org/openshield?style=flat-square)](https://github.com/openshield-org/openshield/issues)
[![GitHub license](https://img.shields.io/github/license/openshield-org/openshield?style=flat-square)](LICENSE)
[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![CI](https://github.com/openshield-org/openshield/actions/workflows/ci.yml/badge.svg?branch=dev)](https://github.com/openshield-org/openshield/actions/workflows/ci.yml)
[![Deploy](https://github.com/openshield-org/openshield/actions/workflows/deploy.yml/badge.svg?branch=dev)](https://github.com/openshield-org/openshield/actions/workflows/deploy.yml)
[![Security Policy](https://img.shields.io/badge/security-policy-green.svg)](.github/SECURITY.md)
[![OWASP](https://img.shields.io/badge/OWASP-listing%20review-orange.svg)](https://owasp.org)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)
[![Discord](https://img.shields.io/badge/Discord-Join%20Us-7289da)](https://discord.gg/openshield)

---

## The Problem

Enterprise cloud security tools like **Wiz**, **Prisma Cloud**, and **Microsoft Defender for Cloud** cost **$50,000–$500,000/year**.

Startups, SMEs, universities, and student teams are left with **zero visibility** into their Azure security posture. A misconfigured storage blob, an overprivileged service principal, or an open NSG rule can sit undetected for months.

**OpenShield changes that.**

## Why Post-Quantum Cryptography Matters Now

Adversaries are collecting encrypted Azure traffic today to decrypt it when quantum computers become available. This is called a Harvest Now Decrypt Later attack and it is happening right now.

OpenShield scans Azure for classical cryptographic assets that need migration before it is too late:

- TLS configurations using RSA or ECDH key exchange on App Services
- Key Vault keys using RSA or ECC algorithms vulnerable to Shor's algorithm
- Certificates using classical signature algorithms

Findings map to NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) and feed directly into post-quantum migration planning.

---

## What OpenShield Does

| Feature | Description |
|---|---|
| **Misconfiguration Scanner** | Runs 30+ Azure security rules across storage, network, identity, database, compute, Key Vault, and post-quantum cryptography |
| **Compliance Mapper** | Maps findings to CIS Benchmarks, NIST CSF, ISO 27001, and SOC 2 framework JSON files |
| **Scan History API** | Stores scans and findings in PostgreSQL and exposes findings, score, scan history, and compliance posture over REST |
| **Remediation Playbooks** | Every current rule ships with a matching Azure CLI remediation script |
| **Security Dashboard** | Frontend scaffold is present; the React dashboard MVP is still on the roadmap |
| **Sentinel Integration** | Normalises findings and pushes them into Microsoft Sentinel via a Log Analytics custom table and KQL analytics rules |

---

## Architecture

```mermaid
flowchart TD
    A["React Dashboard MVP\nPlanned frontend"]
    B["Flask REST API\nJWT · CORS · Blueprints"]
    C["Scanner Engine\n30+ Python rules"]
    D["Azure Subscription\nScanned via Azure SDK + Graph"]
    E["Compliance Framework JSON\nCIS · NIST · ISO 27001 · SOC 2"]
    F["PostgreSQL Database\nFindings · Scans"]
    G["Azure CLI Playbooks\n30+ remediation scripts"]
    H["sentinel/ingest.py\nNormalise + HMAC upload"]
    I["Microsoft Sentinel\nOpenShieldFindings_CL · KQL rules"]

    A -->|REST calls| B
    B -->|trigger scans| C
    B -->|read/write| F
    B -->|compliance score| E
    C -->|Azure SDK + Graph| D
    C -->|findings| F
    C -->|scan output JSON| H
    G -->|manual fixes| D
    H -->|Data Collector API| I
    I -->|alerts| A
```

## Live API

The OpenShield API is deployed to the Render free tier and is accessible at:

**`https://openshield-api.onrender.com`**

> **Note:** As this is hosted on the Render free tier, the service may spin down after 15 minutes of inactivity. The first request after a spin-down can take 30-60 seconds to complete.

> [!IMPORTANT]
> **Security Requirement:** Production deployments **fail at startup** if `JWT_SECRET` is missing, set to the insecure default, or shorter than 32 characters. Generate a strong secret with:
> ```
> python -c "import secrets; print(secrets.token_urlsafe(32))"
> ```
> Set `OPENSHIELD_ENV=production` (or rely on Render's automatic `RENDER=true`) to enable this enforcement. Local development runs without these signals are allowed to use the default with a warning.

---

## Tech Stack

| Layer | Technology | Cost |
|---|---|---|
| Frontend | Scaffolded dashboard app (React + Tailwind planned) | Free |
| Backend API | Python + Flask | Free |
| Database | PostgreSQL | Free (Render/Azure free tier) |
| Cloud Scanner | Python + Azure SDK | Free |
| Remediation | Azure CLI playbooks | Free |
| SIEM | Microsoft Sentinel | 90-day free trial |
| CI/CD | GitHub Actions | Free |
| Repo | GitHub | Free |

---

## Project Structure

```
openshield/
├── scanner/               # Azure misconfiguration rule engine
│   ├── rules/             # Individual scan rules (contribute here!)
│   ├── engine.py          # Core scanning orchestration
│   └── azure_client.py    # Azure SDK wrapper
├── compliance/            # Framework mapping engine
│   └── frameworks/        # CIS, NIST, ISO 27001, SOC 2 mappings
├── playbooks/             # Remediation playbooks
│   ├── arm/               # Reserved for future ARM templates
│   ├── terraform/         # Reserved for future Terraform fixes
│   └── cli/               # Azure CLI scripts
├── api/                   # Flask REST API
│   ├── routes/
│   └── models/
├── frontend/              # Dashboard scaffold
├── sentinel/              # Sentinel integration & KQL rules
├── .github/workflows/     # CI checks
├── docs/                  # Documentation
├── CONTRIBUTING.md
└── README.md
```

---


## Quick Start

```bash
# Clone the repo
git clone https://github.com/openshield-org/openshield.git
cd openshield

# Install Python dependencies
pip install -r requirements.txt

# Set your Azure credentials
export AZURE_SUBSCRIPTION_ID=your-subscription-id
export AZURE_CLIENT_ID=your-client-id
export AZURE_CLIENT_SECRET=your-client-secret
export AZURE_TENANT_ID=your-tenant-id

# Run a scan
python -c "
from scanner.engine import ScanEngine
import json, os
result = ScanEngine(os.environ['AZURE_SUBSCRIPTION_ID']).run_scan()
print(json.dumps(result, indent=2))
"

# Start the API
FLASK_APP=api/app.py flask run
```

---

## Contributing

We actively welcome contributions from students and developers at all levels.

**Ways to contribute:**
- Add a new misconfiguration scan rule
- Add a compliance framework mapping
- Write a remediation playbook
- Fix a bug
- Improve documentation

See [CONTRIBUTING.md](CONTRIBUTING.md) for a full guide — including how to add your first rule in under 30 minutes.

Contributors are credited below.

---

## Roadmap

- [x] Project scaffolding
- [x] Core scanner engine (Azure SDK integration)
- [x] 30+ scan rules
- [x] Flask API + PostgreSQL schema
- [x] Post-quantum cryptography scanner (AZ-PQC-001 to AZ-PQC-003)
- [ ] React dashboard MVP
- [x] CIS Benchmark compliance mapping
- [x] SOC 2 compliance mapping
- [x] Sentinel alert integration
- [x] Real-world breach scenarios documented
- [x] First external contributor PR merged
- [x] Azure CLI remediation playbook library
- [x] NIST CSF + ISO 27001 mappings
- [x] GitHub Actions CI pipeline
- [ ] Multi-cloud support (AWS, GCP)

---

## License

MIT — free to use, modify, and distribute.

---

> Built with ❤️ by security engineers and students who believe cloud security tooling should be accessible to everyone.

---

## Learn OpenShield

Explore the OpenShield learning portal to understand:

- Azure CSPM fundamentals
- OpenShield architecture
- Compliance mappings
- Remediation workflows
- Contributor onboarding
- Documentation navigation

👉 [OpenShield Learn](docs/learn/index.html)
> Built by security engineers and students who believe cloud security tooling should be accessible to everyone.
