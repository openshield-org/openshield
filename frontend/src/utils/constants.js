export const RISK_LEVELS = {
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  NONE: 'NONE',
};

export const SEVERITY_LEVELS = {
  HIGH: 'HIGH',
  MEDIUM: 'MEDIUM',
  LOW: 'LOW',
  INFO: 'INFO',
};

export const CATEGORIES = [
  'Storage',
  'Compute',
  'Network',
  'Identity',
  'Database',
  'KeyVault',
  'Monitoring',
];

export const FRAMEWORKS = ['CIS', 'NIST', 'ISO27001', 'SOC2'];

export const DRIFT_TYPES = {
  ADDED: 'ADDED',
  REMOVED: 'REMOVED',
  MODIFIED: 'MODIFIED',
};

export const RISK_COLORS = {
  HIGH: 'text-severity-high bg-red-50 dark:bg-red-900/20',
  MEDIUM: 'text-severity-medium bg-orange-50 dark:bg-orange-900/20',
  LOW: 'text-severity-low bg-green-50 dark:bg-green-900/20',
  NONE: 'text-text-secondary bg-bg-secondary dark:bg-bg-dark-tertiary',
  INFO: 'text-severity-info bg-gray-50 dark:bg-gray-900/20',
};

export const NAV_ITEMS = [
  { path: '/monitoring', label: 'Monitor', icon: 'FiActivity' },
  { path: '/discovery', label: 'Discover', icon: 'FiSearch' },
  { path: '/prioritization', label: 'Prioritize', icon: 'FiTarget' },
  { path: '/scan', label: 'Scan', icon: 'FiZap' },
  { path: '/compliance', label: 'Comply', icon: 'FiShield' },
  { path: '/drift', label: 'Drift', icon: 'FiGitBranch' },
  { path: '/ai', label: 'AI', icon: 'FiCpu' },
];
