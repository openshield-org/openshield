import assert from 'node:assert/strict';
import { DEFAULT_LOCALE, messages, translate } from './messages.js';

const referenceKeys = Object.keys(messages[DEFAULT_LOCALE]).sort();
for (const [locale, catalog] of Object.entries(messages)) {
  assert.deepEqual(Object.keys(catalog).sort(), referenceKeys, `${locale} must contain the complete message catalog`);
}
assert.equal(translate('es', 'nav.monitoring'), 'Monitorear');
assert.equal(translate('unknown', 'nav.monitoring'), 'Monitor');
assert.equal(translate('en', 'scan.scanning', { seconds: 12 }), 'Scanning… 12s');
console.log('i18n catalogs valid');
