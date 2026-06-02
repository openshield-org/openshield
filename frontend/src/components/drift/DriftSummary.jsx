import React from 'react';
import { FiPlusCircle, FiMinusCircle, FiEdit } from 'react-icons/fi';
import Card from '../shared/Card';

export default function DriftSummary({ summary }) {
  const items = [
    { label: 'Added', value: summary.added, Icon: FiPlusCircle, color: 'text-brand-primary', bg: 'bg-green-50 dark:bg-green-900/20' },
    { label: 'Removed', value: summary.removed, Icon: FiMinusCircle, color: 'text-severity-high', bg: 'bg-red-50 dark:bg-red-900/20' },
    { label: 'Modified', value: summary.modified, Icon: FiEdit, color: 'text-severity-medium', bg: 'bg-orange-50 dark:bg-orange-900/20' },
    { label: 'Total Changes', value: summary.total, Icon: FiEdit, color: 'text-status-info', bg: 'bg-blue-50 dark:bg-blue-900/20' },
  ];

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {items.map(({ label, value, Icon, color, bg }) => (
        <Card key={label} className="p-4 flex items-center gap-4">
          <div className={`w-10 h-10 rounded-lg flex items-center justify-center flex-shrink-0 ${bg}`}>
            <Icon size={18} className={color} />
          </div>
          <div>
            <p className="text-2xl font-bold text-text-primary dark:text-text-dark-primary">{value}</p>
            <p className="text-xs text-text-secondary dark:text-text-dark-tertiary">{label}</p>
          </div>
        </Card>
      ))}
    </div>
  );
}
