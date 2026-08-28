// Tests that a null/NO_SCAN_DATA score from the backend is preserved as
// "no data", never coerced into a real-looking 0 (issue #302). Covers the
// three states get_score()/get_compliance_score() can return: NO_SCAN_DATA
// (no completed scan exists), NO_IN_SCOPE_CONTROLS (a scan exists but every
// mapped control is excluded from the denominator), and a genuinely
// evaluated OK score.
//
// frontend/ has no test runner configured (only eslint + vite). This loads
// the real source (no duplication of the logic under test), neutralizes the
// one Vite-only construct (import.meta.env), and evaluates it with a
// stubbed fetch/localStorage — matching the pattern in aiApi.test.mjs.
//
// Run with: node frontend/src/utils/api.test.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function loadApiModule(fetchImpl) {
  let source = readFileSync(path.join(__dirname, 'api.js'), 'utf8');

  source = source.replace(
    /import\.meta\.env\.VITE_API_URL\s*\|\|\s*\(import\.meta\.env\.DEV \? '[^']*' : '[^']*'\)/,
    "'http://localhost:5000'",
  );
  assert.ok(!source.includes('import.meta'), 'failed to neutralize import.meta usage — test harness is stale');

  // normalizeScore()/normalizeComplianceFramework() (what this file actually
  // tests) never call normalizeRisk()/normalizeSeverity() themselves - those
  // belong to severity.js and have their own dedicated tests
  // (npm run test:severity). Stubbed here (not inlined) so this file stays
  // scoped to what it's actually testing, rather than re-executing a second
  // module's already-tested logic; the stub only needs to satisfy the
  // functions in this file that reference the names at module scope.
  assert.ok(
    source.includes("import { normalizeRisk, normalizeSeverity } from './severity.js';"),
    'expected severity.js import — test harness is stale',
  );
  source = source.replace(
    "import { normalizeRisk, normalizeSeverity } from './severity.js';",
    'const normalizeRisk = (value) => value; const normalizeSeverity = (value) => value;',
  );

  source = source.replace(/^export const /gm, 'const ');
  source = source.replace(/^export default api;\s*$/m, '');
  source += '\nreturn { api, normalizeScore, normalizeComplianceFramework };';

  const localStorageStub = {
    getItem: () => null,
    setItem: () => {},
    removeItem: () => {},
  };

  const load = new Function('localStorage', 'fetch', source);
  return load(localStorageStub, fetchImpl);
}

function jsonResponse(body) {
  return Promise.resolve({ ok: true, status: 200, statusText: 'OK', json: () => Promise.resolve(body) });
}

let failures = 0;
function check(description, fn) {
  try {
    fn();
    console.log(`PASS: ${description}`);
  } catch (err) {
    failures += 1;
    console.error(`FAIL: ${description}`);
    console.error(`  ${err.message}`);
  }
}

async function checkAsync(description, fn) {
  try {
    await fn();
    console.log(`PASS: ${description}`);
  } catch (err) {
    failures += 1;
    console.error(`FAIL: ${description}`);
    console.error(`  ${err.message}`);
  }
}

// ── normalizeScore ───────────────────────────────────────────────────────

{
  const { normalizeScore } = loadApiModule(() => Promise.reject(new Error('fetch should not be called')));

  check('normalizeScore preserves null score and NO_SCAN_DATA status, never coerces to 0', () => {
    const result = normalizeScore({ status: 'NO_SCAN_DATA', score: null, message: 'no completed scan' });
    assert.equal(result.status, 'NO_SCAN_DATA');
    assert.equal(result.score, null);
    assert.equal(result.max_score, 100);
  });

  check('normalizeScore passes through a genuinely evaluated OK score', () => {
    const result = normalizeScore({ status: 'OK', score: 82 });
    assert.equal(result.status, 'OK');
    assert.equal(result.score, 82);
  });

  check('normalizeScore treats a bare legacy number as OK', () => {
    const result = normalizeScore(75);
    assert.equal(result.status, 'OK');
    assert.equal(result.score, 75);
    assert.equal(result.max_score, 100);
  });
}

// ── normalizeComplianceFramework ─────────────────────────────────────────

{
  const { normalizeComplianceFramework } = loadApiModule(() =>
    Promise.reject(new Error('fetch should not be called')));

  check('normalizeComplianceFramework preserves null score for NO_SCAN_DATA', () => {
    const result = normalizeComplianceFramework(
      { status: 'NO_SCAN_DATA', score_percent: null, framework: 'CIS Azure', version: '2.0', total_controls: 95 },
      'cis',
      '#3b82f6',
    );
    assert.equal(result.status, 'NO_SCAN_DATA');
    assert.equal(result.score, null);
  });

  check('normalizeComplianceFramework preserves null score for NO_IN_SCOPE_CONTROLS', () => {
    const result = normalizeComplianceFramework(
      {
        status: 'NO_IN_SCOPE_CONTROLS',
        score_percent: null,
        framework: 'CIS Azure',
        version: '2.0',
        total_controls: 95,
        passed: 0,
        failed: 0,
      },
      'cis',
      '#3b82f6',
    );
    assert.equal(result.status, 'NO_IN_SCOPE_CONTROLS');
    assert.equal(result.score, null);
  });

  check('normalizeComplianceFramework passes through a genuinely evaluated score', () => {
    const result = normalizeComplianceFramework(
      { status: 'OK', score_percent: 91, framework: 'CIS Azure', version: '2.0', total_controls: 95 },
      'cis',
      '#3b82f6',
    );
    assert.equal(result.status, 'OK');
    assert.equal(result.score, 91);
  });

  check('normalizeComplianceFramework defaults status to OK when the backend omits it (back-compat)', () => {
    const result = normalizeComplianceFramework(
      { score_percent: 50, framework: 'CIS Azure', version: '2.0', total_controls: 95 },
      'cis',
      '#3b82f6',
    );
    assert.equal(result.status, 'OK');
    assert.equal(result.score, 50);
  });
}

// ── end-to-end through api.getScore() with a stubbed fetch ──────────────

await checkAsync('api.getScore() surfaces NO_SCAN_DATA from the real response shape without coercion', async () => {
  const { api } = loadApiModule(() =>
    jsonResponse({ status: 'NO_SCAN_DATA', score: null, message: 'no completed scan' }));
  const result = await api.getScore();
  assert.equal(result.status, 'NO_SCAN_DATA');
  assert.equal(result.score, null);
});

await checkAsync('api.getScore() surfaces a real evaluated score unchanged', async () => {
  const { api } = loadApiModule(() => jsonResponse({ status: 'OK', score: 63 }));
  const result = await api.getScore();
  assert.equal(result.status, 'OK');
  assert.equal(result.score, 63);
});

if (failures > 0) {
  console.error(`\n${failures} test(s) failed.`);
  process.exit(1);
} else {
  console.log('\nAll api.js score-normalization tests passed.');
}
