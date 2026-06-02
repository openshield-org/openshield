import React from 'react';
import { FiExternalLink, FiCheckCircle, FiAlertTriangle } from 'react-icons/fi';

const CVSS_STYLE = (score) => {
  if (score >= 9)   return { label: 'CRITICAL', cls: 'bg-red-100 dark:bg-red-900/30 text-red-600 dark:text-red-400' };
  if (score >= 7)   return { label: 'HIGH',     cls: 'bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400' };
  if (score >= 4)   return { label: 'MEDIUM',   cls: 'bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400' };
  return              { label: 'LOW',      cls: 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' };
};

function SkeletonLine({ w = 'w-full', h = 'h-3' }) {
  return <div className={`animate-pulse rounded bg-bg-secondary dark:bg-bg-dark-tertiary ${w} ${h}`} />;
}

export default function CVEAnalysis({ data, loading }) {
  if (loading) {
    return (
      <div className="space-y-3 p-4">
        <SkeletonLine w="w-1/2" h="h-4" />
        {[1, 2, 3].map((i) => (
          <div key={i} className="space-y-2 p-3 rounded-xl border border-border-light dark:border-border-dark">
            <SkeletonLine w="w-1/3" />
            <SkeletonLine w="w-3/4" />
            <SkeletonLine w="w-1/2" />
          </div>
        ))}
      </div>
    );
  }

  if (!data?.cves?.length) return null;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-[10px] font-bold uppercase tracking-widest text-text-tertiary dark:text-text-dark-tertiary">
          CVE Analysis
        </p>
        <span className="text-[10px] text-text-tertiary dark:text-text-dark-tertiary">
          {data.total} detected
        </span>
      </div>

      <div className="space-y-2">
        {data.cves.map((cve) => {
          const { label, cls } = CVSS_STYLE(cve.cvssScore);
          return (
            <div
              key={cve.id}
              className="p-3 rounded-xl border border-border-light dark:border-border-dark hover:border-brand-primary/30 transition-colors"
            >
              {/* Top row */}
              <div className="flex items-start justify-between gap-2 mb-1.5">
                <div className="flex items-center gap-2 min-w-0">
                  <a
                    href={cve.nvdUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-xs font-mono font-bold text-brand-primary hover:underline flex items-center gap-1 flex-shrink-0"
                    onClick={(e) => e.stopPropagation()}
                  >
                    {cve.id} <FiExternalLink size={10} />
                  </a>
                  <span className={`px-1.5 py-0.5 text-[10px] font-bold rounded ${cls}`}>
                    {cve.cvssScore} {label}
                  </span>
                </div>
                <div className="flex items-center gap-1 text-[10px] text-text-tertiary dark:text-text-dark-tertiary flex-shrink-0">
                  {cve.patchAvailable
                    ? <><FiCheckCircle size={11} className="text-brand-primary" /> Patch available</>
                    : <><FiAlertTriangle size={11} className="text-severity-medium" /> No patch</>
                  }
                </div>
              </div>

              {/* Name */}
              <p className="text-xs font-semibold text-text-primary dark:text-text-dark-secondary mb-1">{cve.name}</p>

              {/* Affected resources */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] text-text-tertiary dark:text-text-dark-tertiary">
                  {cve.affectedCount} resource{cve.affectedCount !== 1 ? 's' : ''}:
                </span>
                {cve.affectedResources.map((r) => (
                  <span key={r} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-bg-secondary dark:bg-bg-dark-tertiary text-text-secondary dark:text-text-dark-tertiary">
                    {r}
                  </span>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
