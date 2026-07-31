import { useEffect, useMemo, useState } from 'react';
import { DEFAULT_LOCALE, messages, translate } from '../i18n/messages';
import { I18nState } from '../i18n/I18nState';
const STORAGE_KEY = 'openshield.locale';

function initialLocale() {
  const stored = window.localStorage.getItem(STORAGE_KEY);
  if (stored && messages[stored]) return stored;
  const browserLocale = window.navigator.language?.split('-')[0];
  return messages[browserLocale] ? browserLocale : DEFAULT_LOCALE;
}

export function I18nProvider({ children }) {
  const [locale, setLocaleState] = useState(initialLocale);

  const setLocale = (nextLocale) => {
    const supported = messages[nextLocale] ? nextLocale : DEFAULT_LOCALE;
    window.localStorage.setItem(STORAGE_KEY, supported);
    setLocaleState(supported);
  };

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const value = useMemo(() => ({
    locale,
    locales: Object.keys(messages),
    setLocale,
    t: (key, values) => translate(locale, key, values),
    formatDate: (value, options) => new Intl.DateTimeFormat(locale, options).format(new Date(value)),
    formatNumber: (value, options) => new Intl.NumberFormat(locale, options).format(value),
  }), [locale]);

  return <I18nState.Provider value={value}>{children}</I18nState.Provider>;
}
