import React, { useEffect, useState } from 'react';
import { FiLayout, FiTerminal, FiClock, FiArrowRight, FiTool, FiAlertTriangle } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';

const EFFORT_ETA = { 1: '15–30 mins', 2: '1–2 hours', 3: '2–4 hours', 4: '~1 day', 5: '2–3 days' };

const IMPACT_STYLES = {
  CRITICAL: 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-800',
  HIGH:     'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400 border border-orange-200 dark:border-orange-800',
  MEDIUM:   'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 border border-yellow-200 dark:border-yellow-800',
  LOW:      'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 border border-green-200 dark:border-green-800',
};

const EFFORT_LABEL = { 1: 'LOW', 2: 'LOW', 3: 'MEDIUM', 4: 'HIGH', 5: 'HIGH' };

function trunc(str, max) {
  if (!str) return null;
  return str.length > max ? str.slice(0, max) + '…' : str;
}

export default function QuickRemediation({ ranking, finding }) {
  const navigate = useNavigate();
  const [visible, setVisible] = useState(false);

  // Fade-in on mount and on issue change
  useEffect(() => {
    setVisible(false);
    const t = setTimeout(() => setVisible(true), 20);
    return () => clearTimeout(t);
  }, [ranking?.ruleId]);

  if (!ranking) return null;

  const eta = EFFORT_ETA[ranking.effort] ?? '—';
  const effortLabel = EFFORT_LABEL[ranking.effort] ?? 'MEDIUM';
  const portalStep = trunc(finding?.portalSteps?.[0], 65) ?? 'See the Scan page for portal steps';
  const cliCommand = trunc(finding?.cliCommands?.[0], 74);
  const hasFinding = !!finding;

  return (
    <div
      className={`rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary overflow-hidden transition-opacity duration-300 ${visible ? 'opacity-100' : 'opacity-0'}`}
    >
      {/* ── Issue Details ─────────────────────────────── */}
      <div className="px-5 py-4 bg-bg-secondary dark:bg-bg-dark-tertiary border-b border-border-light dark:border-border-dark">
        <p className="text-[10px] font-bold uppercase tracking-widest text-text-tertiary dark:text-text-dark-tertiary mb-2">
          Issue Details
        </p>
        <p className="text-base font-bold text-text-primary dark:text-text-dark-primary leading-snug">{ranking.name}</p>
        <p className="text-xs font-mono text-text-secondary dark:text-text-dark-tertiary mt-1">
          {ranking.resource} · {ranking.category} · Score: <strong>{ranking.score}</strong>
        </p>
        <div className="flex flex-wrap items-center gap-2 mt-3">
          <span className={`px-2.5 py-1 rounded-lg text-xs font-bold ${IMPACT_STYLES[ranking.impact] ?? IMPACT_STYLES.MEDIUM}`}>
            <FiAlertTriangle size={10} className="inline mr-1 -mt-0.5" />
            {ranking.impact} impact
          </span>
          <span className="px-2 py-0.5 text-xs rounded-lg bg-bg-primary dark:bg-bg-dark-secondary border border-border-light dark:border-border-dark text-text-secondary dark:text-text-dark-tertiary">
            {effortLabel} effort
          </span>
          <span className="flex items-center gap-1 text-xs text-text-secondary dark:text-text-dark-tertiary">
            <FiClock size={11} /> {eta}
          </span>
        </div>
      </div>

      {/* ── Quick Remediation ─────────────────────────── */}
      <div className="px-5 py-4">
        <p className="text-[10px] font-bold uppercase tracking-widest text-text-tertiary dark:text-text-dark-tertiary mb-4 flex items-center gap-1.5">
          <FiTool size={11} /> Quick Remediation
        </p>

        <div className="space-y-5">
          {/* Portal step */}
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-lg bg-blue-50 dark:bg-blue-900/20 flex items-center justify-center flex-shrink-0">
              <FiLayout size={14} className="text-status-info" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary dark:text-text-dark-tertiary mb-1">
                Portal Steps
              </p>
              <p className="text-sm text-text-primary dark:text-text-dark-secondary leading-relaxed">
                {portalStep}
              </p>
            </div>
          </div>

          {/* CLI command */}
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-lg bg-bg-secondary dark:bg-bg-dark-tertiary flex items-center justify-center flex-shrink-0">
              <FiTerminal size={14} className="text-text-secondary dark:text-text-dark-tertiary" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary dark:text-text-dark-tertiary mb-1">
                CLI Command
              </p>
              {cliCommand ? (
                <code className="block w-full text-xs font-mono bg-bg-dark-primary dark:bg-black text-green-400 px-3 py-2.5 rounded-lg overflow-x-auto whitespace-nowrap custom-scrollbar">
                  {cliCommand}
                </code>
              ) : (
                <p className="text-sm text-text-tertiary dark:text-text-dark-tertiary italic">
                  Full CLI steps available on the Scan page
                </p>
              )}
            </div>
          </div>

          {/* ETA */}
          <div className="flex gap-3">
            <div className="w-8 h-8 rounded-lg bg-green-50 dark:bg-green-900/20 flex items-center justify-center flex-shrink-0">
              <FiClock size={14} className="text-status-success" />
            </div>
            <div>
              <p className="text-[10px] font-semibold uppercase tracking-wider text-text-tertiary dark:text-text-dark-tertiary mb-1">
                Estimated Time
              </p>
              <p className="text-sm font-bold text-text-primary dark:text-text-dark-primary">{eta}</p>
            </div>
          </div>
        </div>

        {/* View Full Playbook */}
        <div className="mt-5 pt-4 border-t border-border-light dark:border-border-dark flex items-center justify-between">
          <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary">
            {hasFinding ? 'Full playbook with all steps available' : 'Remediation steps in Scan page'}
          </p>
          <button
            onClick={() =>
              navigate('/scan', {
                state: {
                  ruleId: ranking.ruleId,
                  fromPrioritization: true,
                  issueName: ranking.name,
                  resource: ranking.resource,
                  category: ranking.category,
                  score: ranking.score,
                  impact: ranking.impact,
                  rank: ranking.rank,
                },
              })
            }
            className="inline-flex items-center gap-1.5 text-sm font-semibold text-brand-primary hover:text-brand-secondary transition-colors group"
          >
            View Full Playbook
            <FiArrowRight size={14} className="group-hover:translate-x-0.5 transition-transform duration-150" />
          </button>
        </div>
      </div>
    </div>
  );
}
