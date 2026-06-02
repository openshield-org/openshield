import React from 'react';
import { FiClock } from 'react-icons/fi';

const EFFORT_LABEL = { 1: 'LOW', 2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'HIGH' };
const EFFORT_ETA   = { 1: '15–30 mins', 2: '1–2 hours', 3: '2–4 hours', 4: '~1 day', 5: '2–3 days' };

const IMPACT_STYLES = {
  CRITICAL: 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400',
  HIGH:     'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400',
  MEDIUM:   'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-600 dark:text-yellow-400',
  LOW:      'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400',
};

const EFFORT_TEXT_STYLES = {
  LOW:    'text-brand-primary',
  MEDIUM: 'text-severity-medium',
  HIGH:   'text-severity-high',
};

export default function ActionItems({ rankings, selectedId, onSelect }) {
  const items = selectedId
    ? rankings.filter((r) => r.ruleId === selectedId)
    : rankings;

  return (
    <div className="space-y-2">
      {items.map((item, i) => {
        const effortLabel = EFFORT_LABEL[item.effort] ?? 'MEDIUM';
        const eta = EFFORT_ETA[item.effort] ?? '—';
        const impactStyle = IMPACT_STYLES[item.impact] ?? IMPACT_STYLES.MEDIUM;
        const isSelected = item.ruleId === selectedId;

        return (
          <button
            key={item.rank}
            onClick={() => onSelect?.(isSelected ? null : item.ruleId)}
            className={`w-full text-left flex items-start gap-3 p-4 rounded-xl border transition-all duration-150 ${
              isSelected
                ? 'border-brand-primary bg-brand-primary/5 dark:bg-brand-primary/10'
                : onSelect
                  ? 'border-border-light dark:border-border-dark hover:border-brand-primary/40 hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary cursor-pointer'
                  : 'border-border-light dark:border-border-dark'
            }`}
          >
            {/* Rank number */}
            <span className={`w-7 h-7 rounded-full text-xs font-bold flex items-center justify-center flex-shrink-0 mt-0.5 ${isSelected ? 'bg-brand-primary text-white' : 'bg-bg-secondary dark:bg-bg-dark-tertiary text-text-secondary dark:text-text-dark-tertiary'}`}>
              {item.rank}
            </span>

            {/* Main content */}
            <div className="flex-1 min-w-0">
              <p className="text-sm font-semibold text-text-primary dark:text-text-dark-primary leading-snug">
                {item.name}
              </p>
              <p className="text-xs font-mono text-text-tertiary dark:text-text-dark-tertiary mt-0.5">
                {item.resource} · {item.category}
              </p>
              <div className="flex flex-wrap items-center gap-2 mt-2">
                <span className={`px-2 py-0.5 text-xs font-semibold rounded-lg ${impactStyle}`}>
                  {item.impact} impact
                </span>
                <span className={`text-xs font-medium ${EFFORT_TEXT_STYLES[effortLabel]}`}>
                  {effortLabel.toLowerCase()} effort
                </span>
                <span className="flex items-center gap-1 text-xs text-text-tertiary dark:text-text-dark-tertiary">
                  <FiClock size={11} /> {eta}
                </span>
              </div>
            </div>

            {/* Score */}
            <div className="flex-shrink-0 text-right">
              <p className="text-sm font-bold text-text-primary dark:text-text-dark-primary tabular-nums">{item.score}</p>
              <p className="text-[10px] text-text-tertiary dark:text-text-dark-tertiary">score</p>
            </div>
          </button>
        );
      })}
    </div>
  );
}
