# Internationalization

The dashboard uses message catalogs through `I18nContext`. English is the
fallback language and Spanish demonstrates a second complete catalog for core
navigation, page titles, scan controls, status messages and theme controls.

The selected locale is stored locally, applied to the document `lang`
attribute, and used with `Intl.DateTimeFormat` and `Intl.NumberFormat`. An
unsupported locale falls back to English. Security identifiers, Azure resource
names, findings and compliance control IDs are data and are never translated.

## Adding a locale

1. Add a catalog to `frontend/src/i18n/messages.js` using exactly the English
   keys.
2. Translate meaning rather than word order; retain `{name}` placeholders.
3. Add the language's self-name to each catalog.
4. Run `npm run test:i18n`; missing keys fail the catalog test.
5. Review navigation at narrow and wide widths and verify date/number output.

The website remains English-first. Additional website locales should reuse the
same terminology but must not duplicate security data or rule definitions.
