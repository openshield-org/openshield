# OpenShield — Comprehensive Validation Report

> **Base & scope.** This validation was executed against the
> `docs/issue-132-frontend-api-validation-dev` snapshot, which had **44** scanner
> rules at the time. The test deliverables in this branch are rebased onto
> `upstream/dev` (openshield-org), which has since advanced to **45** rules —
> `az_net_015` (public DNS zone enumeration, #106) was added and is now covered by
> a test added in this branch. Counts below have been updated to the 45-rule base.
> Findings were measured during the original docs-branch run and were **not**
> re-measured end-to-end against `upstream/dev` except where noted; the three
> headline code defects (H-1, H-2, M-1) were re-confirmed to still exist on
> `upstream/dev`. Other upstream additions landed after the validation run
> (async scan worker #129, threat-simulation prompt builder #138) were not
> separately validated.

## Executive Summary

OpenShield is in **good functional shape**. The two blockers from the previous
validation run (2026-06-07) are **closed**: with a real `DATABASE_URL` + Postgres
the import-time `KeyError: 'DATABASE_URL'` no longer halts pytest collection, and
the full backend suite runs green. The scanner engine, REST API, database
persistence, AI/RAG layer, CVE/NVD correlation, and frontend build all work.

Rule-test coverage was the largest gap and is now **closed** — every one of the
**45** scanner rules has dedicated compliant + non-compliant unit tests (was 10 of
44 on the docs branch; `az_net_015` coverage was added when rebasing onto
`upstream/dev`). Full backend suite: **170 passed, 0 failed** on the original
`upstream/dev` base; after merging the current `dev` (which added its own test
modules) a 2026-07-08 re-run reports **223 passed, 2 skipped** — the only non-pass
is `test_ai_hallucination_guard.py::test_vector_store_purity`, which requires the
optional `chromadb` package plus a built vector store and is unrelated to this
PR's changes. `scanner/rules` coverage **90%**.

Validation also surfaced **two genuine rule-correctness bugs** (both masked by
bare `except` clauses), one broken AI module, an observability gap in the scan
engine, a Sentinel field-mapping mismatch, outdated dependencies with known CVEs,
and stale documentation counts. None are release-blocking on their own, but the
two scanner-rule bugs defeat the purpose of the affected rules and should be
fixed before the next release.

The live **Render API is currently suspended by its owner** (HTTP 503,
`suspend-by-user`), so live-API validation is blocked; both Vercel sites serve.

---

## Environment

| Field | Value |
|---|---|
| OS | Windows 11 + WSL2 Ubuntu 22.04 (backend), Windows (frontend) |
| Python | 3.11.15 (deadsnakes), native WSL venv |
| Node / npm | v22.14.0 / 10.9.2 |
| Database | PostgreSQL 14 (WSL), `openshield_test` DB |
| Branch | `docs/issue-132-frontend-api-validation-dev` |
| HEAD | `67b6744` |
| Date | 2026-06-21 |

---

## Phase Results

| Phase | Status | Key findings |
|---|---|---|
| 0 — Environment setup | **Pass** | Py 3.11 + Postgres + venv up; `DatabaseManager.run_migrations()` creates `openshield.{findings,scans}`; import-time `DATABASE_URL` blocker resolved |
| 1 — Static checks (CI parity, 8) | **Pass** | 45 rules / 45 playbooks / 4 frameworks (44/44 on the docs branch; `az_net_015` is the +1 on upstream); all 8 checks pass. Playbook `bash -n` failed only due to Windows CRLF checkout (git-stored blobs are LF; CI passes). 2 rules orphaned from frameworks (informational) |
| 2 — Full backend pytest | **Pass** | **87 passed, 0 failed**; 39% coverage; `test_jwt_config.py` collection blocker gone. Found `ai/chunker.py` SyntaxError via coverage warning |
| 3 — Rule-test coverage gap | **Pass** | +73 tests across 6 groups on the docs branch (+3 more for `az_net_015` on upstream); all 45 rules now covered; `scanner/rules` 90%. Surfaced AZ-NET-012 bug |
| 4 — ScanEngine integration | **Pass** | 45 rules load; self-consistent score; error isolation works. Confirmed observability gap; surfaced AZ-NET-009 bug |
| 5 — Local API + smoke test | **Pass** | Pass-1 (empty) 32/32+8 skip; Pass-2 (seeded) 37/38; all 18 routes exercised; playbook + CVE paths exercised after seeding. 1 smoke-test design bug (TC-34) |
| 6 — Frontend | **Pass** | lint 65 err/4 warn (unchanged baseline, cosmetic); build clean (782 kB JS); code-level INT-001–007 verified via normalizer layer |
| 7 — AI / RAG | **Pass** | 219 docs embedded; retriever returns correct top hits; `test_ai_insights.py` 24/24; 400/401/502 validation paths confirmed |
| 8 — CVE / NVD / Sentinel | **Pass** | CVE+NVD 27/27; on the docs snapshot `test_worker.py` was absent (it now exists on upstream via #129 and is included in the 170-test suite); Sentinel has no automated tests; HMAC signing correct; Sentinel field-mapping bug found |
| 9 — Security | **Pass** | JWT fail-closed 7/7; CORS `*` warning fires; SQL parameterized (no injection); no hardcoded creds; dep CVEs + missing rate limiting noted |
| 10 — Documentation | **Partial** | Docs-branch counts stale (39/36 → 44/44 at validation; 45/45 on upstream); architecture identity table 4→9 and PQC category missing. Upstream docs not re-audited |
| 11 — Live environments | **Partial / Blocked** | Render API **suspended by owner** (503); Vercel dashboard + website serve (HTTP 200) |
| Azure live scan | **Deferred** | Needs real credentials (see checklist) |

---

## Prioritized Issue List

### Critical
*(none)*

### High

**H-1 — `AZ-NET-009` silently never fires (false negative).**
`scanner/rules/az_net_009.py:36` calls `client.virtual_network_gateway_connections.list_all()`,
but the real `azure-mgmt-network` SDK exposes only `.list(resource_group)` on that
operations group — there is **no `list_all()`** (verified: application_gateways,
load_balancers, virtual_networks all have `list_all`; only this one does not). The
bare `except Exception` at `az_net_009.py:37` swallows the `AttributeError`, so the
rule always returns `[]` and can never detect an IKEv1 VPN gateway.
*Impact:* a security blind spot — the misconfiguration this rule targets is never reported.
*Fix:* iterate resource groups and call `.list(rg)`, or use the correct list-all method.

**H-2 — `AZ-NET-012` false-positives on every NSG.**
`scanner/rules/az_net_012.py:48` calls `azure_client.get_nsg_flow_logs(resource_group)`,
but `scanner/azure_client.py` has **no `get_nsg_flow_logs` method**. The
`AttributeError` is swallowed by the bare `except` at `az_net_012.py:56`, leaving
`flow_log_enabled = False`, so **every NSG** is flagged "NSG Flow Logs Not Enabled"
regardless of real configuration.
*Impact:* guaranteed false positives on every scan; erodes trust and buries real findings.
*Fix:* implement `AzureClient.get_nsg_flow_logs()` (Network Watcher flow-logs API), or
change the rule to use an existing accessor.

### Medium

**M-1 — `ai/chunker.py` does not import (SyntaxError).**
`ai/chunker.py:37` is `text.rfind("` followed by a literal newline then `", start, end)`
— a string literal with an unescaped newline (should be `"\n"`). The module raises
`SyntaxError` on import. CI misses it because CHECK 6 only `py_compile`s `api/`, not
`ai/`. Blast radius is limited (`chunk_documents()` is imported nowhere; `ai/embed.py`
does its own chunking), but `ai/README.md` documents it as part of the pipeline.
*Fix:* `"\n"`; and extend the CI syntax check to cover `ai/` (and `sentinel/`).

**M-2 — ScanEngine swallows failed rules with no observability.**
`scanner/engine.py:127` logs a rule exception and continues (good — error isolation
works), but `run_scan()`'s result dict has **no field** listing which rules errored.
A partial scan (rules silently failing) is indistinguishable from a clean scan to the
API/dashboard. *Fix:* add an `errored_rules` list to the result and surface it via the API.

**M-3 — Sentinel ingest drops compliance fields with real scan data.**
`sentinel/ingest.py:36-37` reads `raw.get("compliance",{}).get("cis"/"nist")`, but the
real scanner emits `frameworks` with UPPERCASE keys (`{"CIS": ..., "NIST": ...}`). With
actual `ScanEngine` output, `CisControl`/`NistControl` are always blank. The April-2026
`TEST_PLAN.md` passed only because `generate_test_findings.py` produces synthetic
findings matching the ingest code's `compliance.cis` shape (and `OS-00x` IDs), not the
real scanner's. *Fix:* read `frameworks` with case-insensitive keys.

**M-4 — Dependencies pinned to versions with known CVEs.**
`pip-audit`: 34 advisories across 9 packages — notably **`pyjwt 2.8.0`** (auth library),
`flask-cors 4.0.0` (CVE-2024-6844/6866/6839), `gunicorn 21.2.0` (CVE-2024-1135 request
smuggling), `requests 2.31.0` (CVE-2024-35195), `cryptography 42.0.5`, `flask 3.0.0`,
`azure-identity 1.15.0`. `npm audit`: 1 HIGH in `vite` (dev-server only).
*Fix:* bump pins; prioritize `pyjwt`, `flask-cors`, `gunicorn`, `requests`.

**M-5 — Documentation counts are stale.**
*(Audited on the `docs/issue-132` snapshot; line numbers and exact text refer to that
branch's docs. Upstream `README.md`/`docs/architecture.md` were not re-audited and may
differ.)* `README.md:47` "39 rules" and `:50` "36 playbooks" (also `:63`/`:67` diagrams
"39"); `docs/architecture.md:5`/`:113` "36 rules", `:46` "20 rule files"; the architecture
rule-category table (`:117-122`) lists Identity as 4 (actually 9) and **omits the PQC
category (3 rules)**, summing to 36. Actual code at validation time: 44 rules / 44
playbooks (now **45 / 45** on `upstream/dev`).

### Low / Informational

- **L-1** `tests/smoke_test.py` TC-34 fails on a seeded DB: TC-33 and TC-34 both `POST`
  the same idempotent `/api/scans/<id>/enrich`; the 2nd call returns
  `{"message":"Scan already enriched"}` (no `status`) at `api/routes/scans.py:100`, so
  TC-34's `status=="COMPLETED"` check fails. App behavior is correct; the test makes a
  duplicate call. Net effect: smoke test exits 1 on any already-enriched scan.
- **L-2** `tests/smoke_test.py` duplicates the TC-24/25/26/27/28 blocks (copy-paste).
- **L-3** `AZ-KV-003` and `AZ-NET-012` rule IDs are not referenced by any
  `compliance/frameworks/*.json` — they never surface on the Compliance page. CI CHECK 7
  only validates the forward direction so it doesn't catch this.
- **L-4** No `.gitattributes`; with `core.autocrlf=true` the `.sh` playbooks check out as
  CRLF on Windows and fail `bash -n` locally. Add `*.sh text eol=lf`.
- **L-5** CORS defaults to `*` when `ALLOWED_ORIGINS` unset (`api/app.py:108`) — pre-prod
  hardening item.
- **L-6** No rate limiting on any endpoint (informational for an OSS project at this stage).
- **L-7** `api/routes/findings.py:10-12` defines `_PLAYBOOKS_DIR` twice (dead line).
- **L-8** Compliance controls table lacks per-control `severity`/`category`/`resources`
  (`get_compliance_score` omits them; the frontend defaults to MEDIUM/General/0) —
  cosmetic, graceful.
- **L-9** `tailwind.config.js` `no-undef` lint error (`module` not defined) — CommonJS
  file not excluded from the ESM lint config.
- **Note (docs-branch vs upstream).** On the validated `docs/issue-132` snapshot, the
  5th AI route `/api/ai/threat-simulation`, `tests/test_worker.py`, and `az_net_015` were
  **all absent** (only 4 AI routes existed). On `upstream/dev` all three have since landed
  (`az_net_015` #106 — now covered by a test added in this branch; async worker + 
  `tests/test_worker.py` #129; `/api/ai/threat-simulation` route #138, making 5 AI routes).
  These upstream additions were **not** separately validated in this pass.

---

## Test Deliverables (kept)

| File | Change |
|---|---|
| `tests/test_rules_compute.py` | **new** — 9 tests (AZ-CMP-001..004) |
| `tests/test_rules_identity.py` | +16 tests (AZ-IDN-002..009; Graph/SDK monkeypatched) |
| `tests/test_rules_network.py` | +27 tests (AZ-NET-003..014; +AZ-NET-015 on upstream) |
| `tests/test_rules_keyvault.py` | +9 tests (AZ-KV-001,003..005) |
| `tests/test_rules_database.py` | +6 tests (AZ-DB-001..003) |
| `tests/test_rules_storage.py` | +6 tests (AZ-STOR-003..005) |
| `tests/test_engine_integration.py` | **new** — 4 ScanEngine orchestration tests |
| `tests/helpers/mock_azure.py` | extended additively (~30 accessors incl. DNS zones/record-sets + credential stub) |

Test counts after additions:

- `pytest -q` (full backend suite): **170 passed, 0 failed** on the original
  `upstream/dev` base (was 164 on the docs branch — upstream adds its own tests incl.
  `test_worker.py`, plus the 3 `az_net_015` tests added here). After merging the current
  `dev`, the 2026-07-08 re-run reports **223 passed, 2 skipped**; the lone non-pass is
  `test_ai_hallucination_guard.py::test_vector_store_purity` (needs optional `chromadb`
  + a built vector store — an environment prerequisite, not a code regression, and not
  a file this PR touches).
- `pytest tests/test_rules_*.py -q` (CI rule-regression slice): **92 passed** (was 89; +3
  for `az_net_015`)
- `pytest tests/test_engine_integration.py -q`: **4 passed**

### Scope of the AZ-NET-009 and AZ-NET-012 tests

The new tests for **AZ-NET-009** (`tests/test_rules_network.py`) and **AZ-NET-012**
(same file) validate the rules' **intended isolated detection logic — not current
production integration.** Both tests deliberately supply, via the mock/fake client,
a method the real code path lacks:

- AZ-NET-009: the fake `NetworkManagementClient` exposes
  `virtual_network_gateway_connections.list_all()`, which the real `azure-mgmt-network`
  SDK does **not** provide (only `.list(resource_group)`).
- AZ-NET-012: `MockAzureClient.get_nsg_flow_logs(resource_group)` exists, but the real
  `scanner/azure_client.py` has **no `get_nsg_flow_logs` method at all**.

These tests therefore pass against the *expected* contract and prove the rules' branch
logic is sound, but they do **not** reproduce the production behaviour (a swallowed
`AttributeError` → AZ-NET-009 never fires / AZ-NET-012 always fires). They are kept to
lock in correct logic once H-1/H-2 are fixed; the bugs themselves are tracked above and
must be fixed in production code (`scanner/`), which this validation pass did not touch.

---

## Deferred — Azure live scan (needs real credentials)

Do **not** fabricate values. When a sandbox/non-production subscription is available:

```bash
export AZURE_SUBSCRIPTION_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_TENANT_ID=...
```

Then run **one** of:

```bash
# Direct engine scan
python -c "from scanner.engine import ScanEngine; import json,os; print(json.dumps(ScanEngine(os.environ['AZURE_SUBSCRIPTION_ID']).run_scan(), indent=2))"

# Or via the running API
#   POST /api/scans/trigger  (JWT required), then poll GET /api/scans
# Or the credential-gated smoke tests
RUN_REAL_SCAN=true python tests/smoke_test.py
```

**Safety pre-check before any real run:** re-read all 45 rules' `scan()` calls to confirm
every Azure SDK call is read-only (`.list*` / `.get*` only — no create/update/delete).
Spot-checks during this pass found only read calls, but do a final sweep.

**Expected real-scan caveats given the bugs above:** AZ-NET-009 will report nothing
(H-1) and AZ-NET-012 will flag every NSG (H-2) until fixed.

Also deferred: **live Sentinel ingestion** (needs Log Analytics workspace ID + shared key)
and a **real LLM completion** against `/api/ai/*` (BYOK — opportunistic only).
