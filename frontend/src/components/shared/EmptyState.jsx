import React from 'react';
import { FiInbox } from 'react-icons/fi';

export default function EmptyState({ icon: Icon = FiInbox, title = 'No data found', description = 'There is nothing to display here.' }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <div className="w-14 h-14 rounded-2xl bg-bg-secondary dark:bg-bg-dark-tertiary flex items-center justify-center mb-4">
        <Icon size={24} className="text-text-tertiary dark:text-text-dark-tertiary" />
      </div>
      <p className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-1">{title}</p>
      <p className="text-sm text-text-secondary dark:text-text-dark-tertiary max-w-xs">{description}</p>
    </div>
  );
}
