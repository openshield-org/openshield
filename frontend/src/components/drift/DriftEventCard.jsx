import React from 'react';
import { FiPlusCircle, FiMinusCircle, FiEdit, FiAlertTriangle, FiUser, FiClock } from 'react-icons/fi';
import SeverityBadge from '../shared/SeverityBadge';
import { formatDateTime } from '../../utils/helpers';

const TYPE_CONFIG = {
  ADDED: { Icon: FiPlusCircle, color: 'text-brand-primary', bg: 'bg-green-50 dark:bg-green-900/20' },
  REMOVED: { Icon: FiMinusCircle, color: 'text-severity-high', bg: 'bg-red-50 dark:bg-red-900/20' },
  MODIFIED: { Icon: FiEdit, color: 'text-severity-medium', bg: 'bg-orange-50 dark:bg-orange-900/20' },
};

export default function DriftEventCard({ event }) {
  const { Icon, color, bg } = TYPE_CONFIG[event.type] || TYPE_CONFIG.MODIFIED;

  return (
    <div className="p-4 rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary hover:shadow-soft-lg transition-all duration-200">
      <div className="flex items-start gap-4">
        <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${bg}`}>
          <Icon size={16} className={color} />
        </div>

        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2 mb-1">
            <p className="text-sm font-semibold text-text-primary dark:text-text-dark-primary truncate">{event.resourceName}</p>
            <div className="flex items-center gap-2 flex-shrink-0">
              {event.ruleViolated && (
                <span className="text-xs font-mono text-severity-high bg-red-50 dark:bg-red-900/20 px-2 py-0.5 rounded">
                  {event.ruleViolated}
                </span>
              )}
              <SeverityBadge severity={event.severity} />
            </div>
          </div>

          <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mb-2">{event.resourceType} · {event.resourceGroup}</p>

          <div className="p-2.5 rounded-lg bg-bg-secondary dark:bg-bg-dark-tertiary text-xs font-mono mb-3">
            <span className="text-text-secondary dark:text-text-dark-tertiary">{event.field}: </span>
            {event.oldValue && (
              <>
                <span className="text-severity-high line-through">{event.oldValue}</span>
                <span className="text-text-tertiary dark:text-text-dark-tertiary mx-2">→</span>
              </>
            )}
            <span className="text-brand-primary">{event.newValue || 'removed'}</span>
          </div>

          <div className="flex items-center gap-4 text-xs text-text-tertiary dark:text-text-dark-tertiary">
            <span className="flex items-center gap-1"><FiUser size={11} /> {event.changedBy}</span>
            <span className="flex items-center gap-1"><FiClock size={11} /> {formatDateTime(event.changedAt)}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
