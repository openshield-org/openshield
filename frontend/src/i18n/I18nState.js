import { createContext, useContext } from 'react';

export const I18nState = createContext(null);

export function useI18n() {
  const context = useContext(I18nState);
  if (!context) throw new Error('useI18n must be used inside I18nProvider');
  return context;
}
