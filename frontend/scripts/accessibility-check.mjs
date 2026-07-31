import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const sourceRoot = path.join(root, 'src');

function filesUnder(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    return entry.isDirectory() ? filesUnder(full) : [full];
  });
}

const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
assert.match(html, /<html[^>]+lang="[a-z]{2}"/i, 'frontend HTML must declare a language');

for (const file of filesUnder(sourceRoot).filter((item) => /\.(jsx?|html)$/.test(item))) {
  const source = fs.readFileSync(file, 'utf8');
  assert.doesNotMatch(source, /tabIndex=["'{]?[1-9]/, `${file} uses a positive tab order`);
  assert.doesNotMatch(source, /<(div|span)\b[^>]*\bonClick=/, `${file} uses a non-semantic clickable element`);
  for (const image of source.matchAll(/<img\b[^>]*>/g)) {
    assert.match(image[0], /\balt=/, `${file} contains an image without alt text`);
  }
}

console.log('accessibility static checks passed');
