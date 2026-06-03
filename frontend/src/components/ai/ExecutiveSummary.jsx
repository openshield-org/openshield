import React from 'react';
import { FiRefreshCw, FiClock, FiTrendingUp } from 'react-icons/fi';
import { formatDateTime } from '../../utils/helpers';

const IMPACT_STYLES = {
  CRITICAL: 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400',
  HIGH:     'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400',
  MEDIUM:   'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400',
  LOW:      'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400',
};

const COMPLIANCE_COLORS = {
  'CIS Azure':        '#3b82f6',
  'NIST SP 800-53':   '#8b5cf6',
  'ISO 27001':        '#10b981',
  'SOC 2':            '#f59e0b',
};

function SkeletonLine({ w = 'w-full', h = 'h-3' }) {
  return <div className={`animate-pulse rounded bg-bg-secondary dark:bg-bg-dark-tertiary ${w} ${h}`} />;
}

export default function ExecutiveSummary({ summary, loading, onRefresh }) {
  if (loading) {
    return (
      <div className="space-y-4 p-4">
        <SkeletonLine w="w-1/2" h="h-4" />
        <SkeletonLine />
        <SkeletonLine w="w-5/6" />
        <SkeletonLine w="w-3/4" />
        <div className="space-y-2 mt-4">
          {[1, 2, 3].map((i) => <SkeletonLine key={i} w="w-full" h="h-10" />)}
        </div>
      </div>
    );
  }

  if (!summary) return null;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-2">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest text-text-tertiary dark:text-text-dark-tertiary mb-1">
            AI Executive Summary
          </p>
          <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary flex items-center gap-1.5">
            <FiClock size={11} /> Generated {formatDateTime(summary.generatedAt)}
          </p>
        </div>
        <button
          onClick={onRefresh}
          className="p-1.5 rounded-lg text-text-tertiary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors"
          title="Regenerate summary"
        >
          <FiRefreshCw size={13} />
        </button>
      </div>

      {/* Score + trend */}
      <div className="flex items-center gap-3 p-3 rounded-xl bg-bg-secondary dark:bg-bg-dark-tertiary">
        <div className="text-center">
          <p className="text-2xl font-bold text-text-primary dark:text-text-dark-primary">{summary.riskScore}</p>
          <p className="text-[10px] text-text-tertiary dark:text-text-dark-tertiary uppercase tracking-wider">score</p>
        </div>
        <div className="w-px self-stretch bg-border-light dark:bg-border-dark" />
        <div className="flex-1">
          <p className="text-xs text-text-primary dark:text-text-dark-secondary leading-relaxed">{summary.overview}</p>
        </div>
      </div>

      {/* Top priorities */}
      <div>
        <p className="text-[10px] font-bold uppercase tracking-wider text-text-tertiary dark:text-text-dark-tertiary mb-2">
          Top Priorities
        </p>
        <div className="space-y-2">
          {summary.topPriorities.map((p) => (
            <div key={p.rank} className="flex items-start gap-3 p-3 rounded-xl border border-border-light dark:border-border-dark">
              <span className="w-5 h-5 rounded-full bg-brand-primary text-white text-[10px] font-bold flex items-center justify-center flex-shrink-0 mt-0.5">
                {p.rank}
              </span>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold text-text-primary dark:text-text-dark-primary leading-snug">{p.title}</p>
                <p className="text-[10px] font-mono text-text-tertiary dark:text-text-dark-tertiary mt-0.5 truncate">{p.resource}</p>
              </div>
              <div className="flex-shrink-0 text-right">
                <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded ${IMPACT_STYLES[p.impact] ?? IMPACT_STYLES.HIGH}`}>
                  {p.impact}
                </span>
                <p className="text-[10px] text-text-tertiary dark:text-text-dark-tertiary mt-0.5 flex items-center gap-0.5 justify-end">
                  <FiClock size={9} /> {p.eta}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Compliance scores */}
      <div>
        <p className="text-[10px] font-bold uppercase tracking-wider text-text-tertiary dark:text-text-dark-tertiary mb-2">
          Compliance
        </p>
        <div className="space-y-2">
          {Object.entries(summary.complianceStatus).map(([fw, score]) => (
            <div key={fw} className="flex items-center gap-3">
              <span className="text-xs text-text-secondary dark:text-text-dark-tertiary w-28 flex-shrink-0 truncate">{fw}</span>
              <div className="flex-1 bg-bg-secondary dark:bg-bg-dark-tertiary rounded-full h-1.5">
                <div
                  className="h-1.5 rounded-full transition-all duration-700"
                  style={{ width: `${score}%`, background: COMPLIANCE_COLORS[fw] || '#6b7280' }}
                />
              </div>
              <span className="text-xs font-semibold text-text-primary dark:text-text-dark-primary w-9 text-right flex-shrink-0">
                {score}%
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* ETA */}
      <div className="flex items-center gap-2 p-3 rounded-xl bg-brand-primary/5 dark:bg-brand-primary/10 border border-brand-primary/20">
        <FiTrendingUp size={14} className="text-brand-primary flex-shrink-0" />
        <p className="text-xs text-text-primary dark:text-text-dark-secondary">
          Estimated full remediation: <strong>{summary.estimatedRemediationTime}</strong>
        </p>
      </div>
    </div>
  );
}
