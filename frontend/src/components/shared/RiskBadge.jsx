import React from 'react';

const styles = {
  HIGH: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  MEDIUM: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
  LOW: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  NONE: 'bg-gray-100 text-gray-500 dark:bg-gray-800 dark:text-gray-400',
};

export default function RiskBadge({ risk }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-lg text-xs font-semibold uppercase tracking-wider ${styles[risk] || styles.NONE}`}>
      {risk || 'NONE'}
    </span>
  );
}
