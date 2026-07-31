export const DEFAULT_LOCALE = 'en';

export const messages = {
  en: {
    'nav.monitoring': 'Monitor', 'nav.discovery': 'Discover', 'nav.prioritization': 'Prioritize',
    'nav.scan': 'Scan', 'nav.compliance': 'Comply', 'nav.drift': 'Drift', 'nav.ai': 'AI',
    'theme.dark': 'Dark mode', 'theme.light': 'Light mode', 'theme.toggle': 'Toggle colour theme',
    'menu.open': 'Open menu', 'menu.close': 'Close menu', 'nav.primary': 'Primary navigation',
    'language.label': 'Language', 'language.en': 'English', 'language.es': 'Español',
    'page.monitoring.title': 'Security Monitoring', 'page.monitoring.subtitle': 'Overall health score and trends',
    'page.discovery.title': 'Resource Discovery', 'page.discovery.subtitle': 'All resources across your Azure environment',
    'page.prioritization.title': 'Risk Prioritization', 'page.prioritization.subtitle': 'What to fix first based on risk and effort',
    'page.scan.title': 'Detailed Scan', 'page.scan.subtitle': 'Findings with step-by-step remediation playbooks',
    'page.compliance.title': 'Compliance', 'page.compliance.subtitle': 'Framework tracking and control status',
    'page.drift.title': 'Configuration Drift', 'page.drift.subtitle': 'Detect unexpected changes to your environment',
    'page.ai.title': 'AI Assistant', 'page.ai.subtitle': 'Ask questions about your security posture',
    'scan.run': 'Run Scan', 'scan.scanning': 'Scanning… {seconds}s', 'scan.last': 'Last scanned: {date}',
    'status.live': 'Live', 'status.reconnecting': 'Reconnecting', 'skip.content': 'Skip to main content',
  },
  es: {
    'nav.monitoring': 'Monitorear', 'nav.discovery': 'Descubrir', 'nav.prioritization': 'Priorizar',
    'nav.scan': 'Escanear', 'nav.compliance': 'Cumplimiento', 'nav.drift': 'Cambios', 'nav.ai': 'IA',
    'theme.dark': 'Modo oscuro', 'theme.light': 'Modo claro', 'theme.toggle': 'Cambiar tema de color',
    'menu.open': 'Abrir menú', 'menu.close': 'Cerrar menú', 'nav.primary': 'Navegación principal',
    'language.label': 'Idioma', 'language.en': 'English', 'language.es': 'Español',
    'page.monitoring.title': 'Monitoreo de seguridad', 'page.monitoring.subtitle': 'Puntuación general y tendencias',
    'page.discovery.title': 'Descubrimiento de recursos', 'page.discovery.subtitle': 'Recursos del entorno de Azure',
    'page.prioritization.title': 'Priorización de riesgos', 'page.prioritization.subtitle': 'Qué corregir primero según riesgo y esfuerzo',
    'page.scan.title': 'Escaneo detallado', 'page.scan.subtitle': 'Hallazgos y guías de corrección',
    'page.compliance.title': 'Cumplimiento', 'page.compliance.subtitle': 'Controles y marcos de cumplimiento',
    'page.drift.title': 'Cambios de configuración', 'page.drift.subtitle': 'Cambios inesperados del entorno',
    'page.ai.title': 'Asistente de IA', 'page.ai.subtitle': 'Preguntas sobre la postura de seguridad',
    'scan.run': 'Ejecutar escaneo', 'scan.scanning': 'Escaneando… {seconds}s', 'scan.last': 'Último escaneo: {date}',
    'status.live': 'En línea', 'status.reconnecting': 'Reconectando', 'skip.content': 'Saltar al contenido principal',
  },
};

export function translate(locale, key, values = {}) {
  const template = messages[locale]?.[key] ?? messages[DEFAULT_LOCALE][key] ?? key;
  return Object.entries(values).reduce((text, [name, value]) => text.replaceAll(`{${name}}`, String(value)), template);
}
