import React from 'react';
import { FiZap } from 'react-icons/fi';
import SeverityBadge from '../shared/SeverityBadge';

const SEVERITY_BG = {
  HIGH:   'bg-red-50 dark:bg-red-900/20 text-severity-high',
  MEDIUM: 'bg-orange-50 dark:bg-orange-900/20 text-severity-medium',
  LOW:    'bg-green-50 dark:bg-green-900/20 text-severity-low',
};

const RANK_BG = {
  1: 'bg-red-500 text-white',
  2: 'bg-red-400 text-white',
  3: 'bg-red-400 text-white',
  4: 'bg-orange-400 text-white',
  5: 'bg-orange-400 text-white',
  6: 'bg-orange-400 text-white',
  7: 'bg-orange-400 text-white',
};

export default function RiskRanking({ rankings, selectedId, onSelect }) {
  return (
    <div className="space-y-2 overflow-y-auto max-h-[420px] pr-1 custom-scrollbar">
      {rankings.map((item) => {
        const isSelected = item.ruleId === selectedId;
        return (
          <button
            key={item.rank}
            onClick={() => onSelect?.(isSelected ? null : item.ruleId)}
            className={`w-full text-left p-3 rounded-xl border transition-all duration-150 ${
              isSelected
                ? 'border-brand-primary bg-brand-primary/5 dark:bg-brand-primary/10 shadow-soft'
                : 'border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary hover:border-brand-primary/40 hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary'
            }`}
          >
            <div className="flex items-start gap-3">
              {/* Rank badge */}
              <span className={`w-7 h-7 rounded-lg text-xs font-bold flex items-center justify-center flex-shrink-0 mt-0.5 ${RANK_BG[item.rank] || 'bg-bg-secondary dark:bg-bg-dark-tertiary text-text-secondary dark:text-text-dark-tertiary'}`}>
                {item.rank}
              </span>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <p className={`text-sm font-semibold leading-snug ${isSelected ? 'text-brand-primary' : 'text-text-primary dark:text-text-dark-primary'}`}>
                  {item.name}
                </p>
                <div className="flex items-center gap-2 mt-1.5 flex-wrap">
                  <SeverityBadge severity={item.severity} />
                  <span className="text-xs text-text-tertiary dark:text-text-dark-tertiary font-mono">{item.resource}</span>
                  <span className="text-xs text-text-tertiary dark:text-text-dark-tertiary">· {item.category}</span>
                </div>
              </div>

              {/* Score */}
              <div className="flex-shrink-0 text-right">
                <p className={`text-xl font-bold tabular-nums ${isSelected ? 'text-brand-primary' : 'text-text-primary dark:text-text-dark-primary'}`}>
                  {item.score}
                </p>
                <p className="text-[10px] text-text-tertiary dark:text-text-dark-tertiary uppercase tracking-wide">score</p>
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}
