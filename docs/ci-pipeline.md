# CI Pipeline

OpenShield runs a GitHub Actions workflow on every pull request to `dev` and `main`. The workflow contains seven checks. All seven must pass before a PR can merge.

This document explains what each check does, how to run every check locally before opening a PR, and the reasoning behind the testing methods chosen.

---

## Checks at a glance

| # | Check | What fails |
|---|---|---|
| 1 | Python syntax (rule files) | Any `az_*.py` with a syntax error |
| 2 | Rule structure + RULE_ID uniqueness | Missing required fields, invalid SEVERITY, non-dict FRAMEWORKS, duplicate RULE_IDs |
| 3 | Hardcoded credential scan | Literal secrets, keys, or connection strings in source files |
| 4 | Playbook existence + bash syntax | Missing `.sh` for any rule file, or a `.sh` with a bash syntax error |
| 5 | Compliance JSON validation | Missing framework file, invalid JSON, empty object |
| 6 | API syntax check | Any `api/**/*.py` with a syntax error |
| 7 | Compliance rule cross-reference | A rule ID referenced in a framework JSON that has no matching rule file |

The final step always runs and writes a per-check pass/fail table to the GitHub Actions summary panel so reviewers can see the result without reading through logs.

---

## Setup for local runs

Before running any checks locally, install the project dependencies including `pyyaml`, which is required to validate the workflow file as valid YAML.

```bash
pip install -r requirements.txt
```

If you prefer to install only what the local checks need without the full Azure SDK stack:

```bash
pip install pyyaml==6.0.1
```

To verify the workflow file itself is valid YAML before pushing:

```bash
python -c "
import yaml
with open('.github/workflows/ci.yml') as f:
    yaml.safe_load(f)
print('YAML is valid')
"
```

This catches structural problems in the workflow file — misaligned indentation, duplicate keys, bad anchors — that GitHub Actions would reject silently or with a confusing error message.

---

## Running checks locally

Run these from the root of the repository. If any command exits non-zero, CI will also fail.

### Check 1 — Python syntax (rule files)

```bash
for f in scanner/rules/az_*.py; do
  python -m py_compile "$f" && echo "OK: $f" || echo "FAIL: $f"
done
```

A clean run prints `OK:` for every file and exits 0.

---

### Check 2 — Rule structure and RULE_ID uniqueness

```python
python - <<'PYEOF'
import os, importlib.util, sys
from collections import defaultdict

rules_dir = "scanner/rules"
required_fields = ["RULE_ID", "SEVERITY", "FRAMEWORKS"]
valid_severities = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
failures = []
seen_ids = defaultdict(list)

for filename in sorted(os.listdir(rules_dir)):
    if not filename.startswith("az_") or not filename.endswith(".py"):
        continue
    filepath = os.path.join(rules_dir, filename)
    spec = importlib.util.spec_from_file_location("rule", filepath)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        failures.append(f"{filename}: import error — {e}")
        continue
    for field in required_fields:
        if not hasattr(mod, field):
            failures.append(f"{filename}: missing field '{field}'")
    if hasattr(mod, "SEVERITY") and mod.SEVERITY not in valid_severities:
        failures.append(f"{filename}: SEVERITY '{mod.SEVERITY}' is not valid")
    if hasattr(mod, "FRAMEWORKS") and (not isinstance(mod.FRAMEWORKS, dict) or len(mod.FRAMEWORKS) == 0):
        failures.append(f"{filename}: FRAMEWORKS must be a non-empty dict")
    if hasattr(mod, "RULE_ID"):
        seen_ids[mod.RULE_ID].append(filename)

for rule_id, files in seen_ids.items():
    if len(files) > 1:
        failures.append(f"DUPLICATE RULE_ID '{rule_id}' in: {', '.join(files)}")

if failures:
    print("FAILURES:")
    for f in failures: print(f"  - {f}")
    sys.exit(1)
else:
    print(f"All {len(seen_ids)} rule files passed.")
PYEOF
```

---

### Check 3 — Hardcoded credential scan

```bash
PATTERNS=(
  "password\s*="
  "secret\s*="
  "api_key\s*="
  "client_secret\s*="
  "AZURE_CLIENT_SECRET\s*=\s*['\"][^'\"]\+"
  "-----BEGIN.*PRIVATE KEY-----"
  "AccountKey="
)

FAIL=0
for pattern in "${PATTERNS[@]}"; do
  matches=$(grep -rniE "$pattern" \
    --include="*.py" --include="*.sh" --include="*.json" --include="*.yml" \
    --exclude-dir=".git" --exclude-dir="venv" --exclude="ci.yml" \
    . 2>/dev/null | \
    grep -v "\.env" | grep -v "os\.environ" | grep -v "os\.getenv" | \
    grep -v "#" | grep -v "example" | grep -v "placeholder" || true)
  if [ -n "$matches" ]; then
    echo "POTENTIAL LEAK — pattern '$pattern':"
    echo "$matches"
    FAIL=1
  fi
done
[ "$FAIL" -eq 0 ] && echo "No hardcoded credentials found." || echo "FAIL"
```

If this flags a match in your code, replace the literal value with `os.environ["VAR_NAME"]` and store the real value in your `.env` file (which is gitignored).

---

### Check 4 — Playbook existence and bash syntax

```bash
FAIL=0
for rule_file in scanner/rules/az_*.py; do
  filename=$(basename "$rule_file" .py)
  playbook="playbooks/cli/fix_${filename}.sh"
  if [ ! -f "$playbook" ]; then
    echo "MISSING: $playbook"
    FAIL=1
  elif ! bash -n "$playbook" 2>&1; then
    echo "BASH SYNTAX ERROR: $playbook"
    FAIL=1
  else
    echo "OK: $playbook"
  fi
done
[ "$FAIL" -eq 0 ] && echo "All playbooks OK."
```

`bash -n` parses the script without executing it. It catches undefined syntax such as mismatched `if`/`fi`, unclosed quotes, and bad redirects. It does not execute any Azure CLI commands.

---

### Check 5 — Compliance JSON validation

```python
python - <<'PYEOF'
import json, os, sys

framework_dir = "compliance/frameworks"
expected = ["cis_azure_benchmark.json", "nist_csf.json", "iso27001.json", "soc2.json"]
failures = []

for fname in expected:
    fpath = os.path.join(framework_dir, fname)
    if not os.path.exists(fpath):
        failures.append(f"MISSING: {fpath}")
        continue
    try:
        data = json.load(open(fpath))
        n = len(data.get("controls", {}))
        print(f"OK: {fname} ({n} controls)")
    except json.JSONDecodeError as e:
        failures.append(f"{fname}: invalid JSON — {e}")

if failures:
    for f in failures: print(f"  - {f}")
    sys.exit(1)
PYEOF
```

---

### Check 6 — API syntax check

```bash
FAIL=0
if [ -d "api" ]; then
  while IFS= read -r -d '' f; do
    python -m py_compile "$f" && echo "OK: $f" || { echo "FAIL: $f"; FAIL=1; }
  done < <(find api/ -name "*.py" -print0)
else
  echo "No api/ directory — skipping"
fi
[ "$FAIL" -eq 0 ] && echo "API syntax OK."
```

---

### Check 7 — Compliance rule cross-reference

```python
python - <<'PYEOF'
import json, os, importlib.util, sys

rules_dir = "scanner/rules"
framework_dir = "compliance/frameworks"

existing_ids = set()
for filename in os.listdir(rules_dir):
    if not filename.startswith("az_") or not filename.endswith(".py"):
        continue
    spec = importlib.util.spec_from_file_location("rule", os.path.join(rules_dir, filename))
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        if hasattr(mod, "RULE_ID"):
            existing_ids.add(mod.RULE_ID)
    except Exception:
        pass

failures = []
for fname in os.listdir(framework_dir):
    if not fname.endswith(".json"):
        continue
    try:
        data = json.load(open(os.path.join(framework_dir, fname)))
    except Exception:
        continue
    for rule_id in data.get("controls", {}):
        if rule_id not in existing_ids:
            failures.append(f"{fname}: references '{rule_id}' but no rule file found")

if failures:
    for f in failures: print(f"  - {f}")
    sys.exit(1)
else:
    print(f"All compliance controls verified. ({len(existing_ids)} rules checked)")
PYEOF
```

---

## Testing method rationale

### Why `py_compile` and not `flake8` or `pylint`

`py_compile` checks only for syntax errors — the kind that prevent the file from loading at all. Linters add style and convention rules that differ across contributors and would generate noise on code written before the linter was introduced. A syntax check has a binary, objective outcome. That is the right scope for a CI gate on an open source project where contributors are writing their first rules.

### Why `importlib` and not regex for structure validation

Regex on Python source is fragile. A field could be assigned via a helper function, computed from a base class, or split across continuation lines. `importlib.util.spec_from_file_location` actually executes the module and then `hasattr()` checks the resulting object — the only way to be certain the attribute is present and accessible at runtime. This is the same mechanism the scanner engine uses when loading rules, so the CI check mirrors what production does.

### Why `bash -n` and not just checking file existence

An earlier version of this check only verified that a playbook file existed. A `.sh` file with a bash syntax error — an unclosed `if`, a bad heredoc, a missing `fi` — will crash immediately when an operator runs it in response to a real finding. `bash -n` parses without executing, so it catches structural errors at zero risk of touching any Azure resource. Existence alone is not sufficient.

### Why the credential scan uses grep exclusions rather than an allowlist

The patterns being scanned (`password=`, `secret=`, `api_key=`) appear legitimately in two contexts: environment variable lookups (`os.environ`, `os.getenv`) and inline comments. Both are explicitly excluded. The scan is scoped to literal assignment — the pattern that indicates a value is hardcoded in source. A grep-based approach is auditable: every exclusion is visible in one place and any contributor can read exactly what is and is not excluded.

### Why the credential scan excludes `venv/`

On GitHub Actions the checkout is clean with no `venv/`. Locally, `venv/` contains thousands of lines from third-party packages that match patterns like `password=None` as function arguments. Excluding `venv/` prevents false positives when contributors run the check locally without creating a confusing discrepancy between local and CI results.

### Why the cross-reference check walks compliance JSONs rather than rule files

The check is designed to catch a deletion scenario: a rule file is removed but its entry in one or more compliance JSONs is not. Walking the JSONs and looking up each referenced rule ID against the set of existing rule files catches stale references. The inverse check — verifying every rule file has a compliance entry — is not enforced because a rule may legitimately not map to every framework.

---

## Edge cases handled

**Rule file has syntax error but passes `py_compile`**
Not possible. `py_compile` detects all syntax errors that prevent the AST from parsing. If `py_compile` passes, the file can be imported.

**Rule file imports a package not in `requirements.txt`**
Check 2 will fail with `import error` when `spec.loader.exec_module` raises `ModuleNotFoundError`. The error message names the missing package. Add it to `requirements.txt`.

**Two rule files define the same `RULE_ID`**
Check 2 collects all IDs with `defaultdict(list)` before reporting, so it catches every duplicate in a single run rather than stopping at the first. The failure message names both files.

**A playbook file exists but contains only a shebang and no logic**
`bash -n` passes — a script with only `#!/bin/bash` is syntactically valid. This is intentional: a stub playbook during development is acceptable; a broken playbook is not.

**A compliance JSON has a `controls` key with no entries**
Check 5 reports the number of controls but does not fail on zero. An empty `controls` block is structurally valid JSON. Check 7 will simply find nothing to cross-reference. If you want to enforce minimum control counts, add a `len(controls) == 0` check to Check 5.

**The `api/` directory does not exist**
Check 6 prints `No api/ directory found — skipping` and exits 0. The check is designed to be safe to include before the API module is added.

**A framework JSON file references a rule ID that was renamed**
Check 7 catches this. The referenced ID will not be in `existing_ids` (which is built from the current `RULE_ID` attribute of each rule file) and CI fails with the exact JSON file and rule ID that is stale.

**Trailing comma in a compliance JSON**
Check 5 catches this. Python's `json.load` raises `json.JSONDecodeError` on trailing commas, and the failure message includes the line number from the decoder.

**Local `venv/` directory triggers credential scan false positives**
The scan excludes `--exclude-dir=venv`. On GitHub Actions there is no `venv/` to exclude, so the flag is harmless there.

---

## How the CI summary works

The final step uses `if: always()` so it runs regardless of whether earlier steps passed or failed. Each check step has a unique `id`. The summary step reads the outcome of every step via environment variables:

```yaml
- name: CI Summary
  if: always()
  env:
    SYNTAX:    ${{ steps.syntax_check.outcome }}
    STRUCTURE: ${{ steps.structure_check.outcome }}
    ...
```

GitHub Actions sets `outcome` to `success`, `failure`, `skipped`, or `cancelled`. The summary step writes a markdown table to `$GITHUB_STEP_SUMMARY`, which GitHub renders as a panel on the Actions run page. This means a reviewer can see which check failed without opening any log.

When running locally (no `$GITHUB_STEP_SUMMARY` environment variable), the summary is printed to stdout only.

---

## Fixing common failures

| Failure message | Cause | Fix |
|---|---|---|
| `SYNTAX ERROR: scanner/rules/az_xxx_000.py` | Invalid Python syntax | Open the file, find the syntax error, fix it |
| `missing field 'RULE_ID'` | Rule file does not define `RULE_ID` at module level | Add `RULE_ID = "AZ-XXX-000"` at the top of the file |
| `SEVERITY 'MEDIUM-HIGH' not in {...}` | SEVERITY value is not one of the five allowed strings | Change to `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `DUPLICATE RULE_ID 'AZ-NET-003'` | Two rule files declare the same ID | Assign a unique ID to the newer file |
| `POTENTIAL CREDENTIAL LEAK` | A literal secret is present in source | Replace with `os.environ["VAR_NAME"]` |
| `MISSING PLAYBOOK: playbooks/cli/fix_az_xxx_000.sh` | No playbook created for the new rule | Create `playbooks/cli/fix_az_xxx_000.sh` |
| `BASH SYNTAX ERROR: playbooks/cli/fix_az_xxx_000.sh` | Shell script has invalid syntax | Run `bash -n playbooks/cli/fix_az_xxx_000.sh` locally to see the error |
| `invalid JSON — ...` | Trailing comma or other JSON error in a framework file | Open the file, find the bad line (error message includes line number), fix it |
| `references 'AZ-XXX-000' but no matching rule file found` | A compliance JSON references a rule that does not exist | Either create the rule file or remove the entry from the compliance JSON |
