// Minimal, dependency-free test for toEmbedUrl() in script.js (issue #179).
//
// website/ is a plain static site with no build step and no existing test
// framework, so this loads the real script.js source via Node's built-in vm
// module (no duplication of the function under test) with just enough DOM
// stubbing for the file's top-level statements to execute without crashing.
//
// Run with: node website/test_toEmbedUrl.mjs

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import vm from 'node:vm';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const source = readFileSync(path.join(__dirname, 'script.js'), 'utf8');

function stubElement() {
  return {
    addEventListener() {},
    classList: { contains: () => false, add() {}, remove() {}, toggle() {} },
    style: {},
    value: '',
  };
}

const sandbox = {
  window: {
    addEventListener() {},
    requestAnimationFrame() {},
    location: { hash: '' },
    history: { pushState() {} },
    lucide: null,
  },
  document: {
    createElement: () => stubElement(),
    getElementById: () => null,
    querySelectorAll: () => [],
    documentElement: { classList: { contains: () => false } },
    addEventListener() {},
  },
  localStorage: {
    getItem: () => null,
    setItem() {},
    removeItem() {},
  },
  siteContent: { blog: [], terminal: [] },
  marked: { parse: (s) => s },
  console,
  URL,
};
sandbox.window.document = sandbox.document;
vm.createContext(sandbox);
vm.runInContext(source, sandbox, { filename: 'script.js' });

const { toEmbedUrl } = sandbox;
assert.equal(typeof toEmbedUrl, 'function', 'toEmbedUrl must be defined at top level of script.js');

const cases = [
  // [input, expected output, description]
  ['https://www.youtube.com/watch?v=dQw4w9WgXcQ', 'https://www.youtube.com/embed/dQw4w9WgXcQ', 'youtube watch URL'],
  ['https://youtu.be/dQw4w9WgXcQ', 'https://www.youtube.com/embed/dQw4w9WgXcQ', 'youtu.be short URL'],
  ['https://vimeo.com/12345678', 'https://player.vimeo.com/video/12345678', 'vimeo URL'],
  ['https://www.youtube.com/embed/dQw4w9WgXcQ', 'https://www.youtube.com/embed/dQw4w9WgXcQ', 'already-embed youtube URL'],
  ['https://player.vimeo.com/video/12345678', 'https://player.vimeo.com/video/12345678', 'already-embed vimeo URL'],
  ['', '', 'empty input'],
  [null, '', 'null input'],
];

const rejected = [
  // Inputs that must be rejected (return '') because they are not a genuine
  // youtube.com/youtu.be/vimeo.com URL, even though some contain the
  // substring "youtube.com/embed" or "player.vimeo.com" somewhere.
  '"><img src=x onerror=alert(1)>//youtube.com/embed',
  'https://evil.com/?x=youtube.com/embed',
  'https://youtube.com.evil.com/embed',
  'https://notyoutube.com/embed/xyz//player.vimeo.com',
  'javascript:alert(1)',
  'not a url at all but contains youtube.com/embed',
];

// Inputs on an ALLOWED host that still carry an attribute-injection payload.
// The host passes the allowlist, so the earlier "rejected" cases don't cover
// this — the returned value is interpolated into an iframe src="..." attribute,
// so it must never contain a raw double-quote that could break out of it.
// The fix returns the canonicalised URL.href (which percent-encodes quotes and
// spaces) instead of the raw input.
const sanitizedPassthrough = [
  [
    'https://www.youtube.com/embed/abc" onload="alert(1)',
    'https://www.youtube.com/embed/abc%22%20onload=%22alert(1)',
    'attribute-injection payload on allowed host is percent-encoded',
  ],
  [
    'https://player.vimeo.com/video/1"><script>alert(1)</script>',
    'https://player.vimeo.com/video/1%22%3E%3Cscript%3Ealert(1)%3C/script%3E',
    'script-injection payload on allowed vimeo host is percent-encoded',
  ],
];

let failures = 0;

function assertNoDoubleQuote(value, description) {
  assert.ok(
    !String(value).includes('"'),
    `${description}: return value must not contain a raw double-quote (iframe src breakout): ${JSON.stringify(value)}`,
  );
}

for (const [input, expected, description] of cases) {
  const actual = toEmbedUrl(input);
  try {
    assert.equal(actual, expected);
    console.log(`PASS: ${description}`);
  } catch {
    failures++;
    console.error(`FAIL: ${description} — input=${JSON.stringify(input)} got=${JSON.stringify(actual)} want=${JSON.stringify(expected)}`);
  }
}

for (const input of rejected) {
  const actual = toEmbedUrl(input);
  try {
    assert.equal(actual, '');
    console.log(`PASS: rejects bypass attempt (${JSON.stringify(input.slice(0, 40))}...)`);
  } catch {
    failures++;
    console.error(`FAIL: bypass NOT rejected — input=${JSON.stringify(input)} got=${JSON.stringify(actual)}`);
  }
}

for (const [input, expected, description] of sanitizedPassthrough) {
  const actual = toEmbedUrl(input);
  try {
    assert.equal(actual, expected);
    assertNoDoubleQuote(actual, description);
    console.log(`PASS: ${description}`);
  } catch (err) {
    failures++;
    console.error(`FAIL: ${description} — input=${JSON.stringify(input)} got=${JSON.stringify(actual)}\n  ${err.message}`);
  }
}

if (failures > 0) {
  console.error(`\n${failures} test(s) failed`);
  process.exit(1);
}
console.log('\nAll toEmbedUrl tests passed');
