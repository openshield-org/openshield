import React from 'react';
import { FiCalendar, FiBox } from 'react-icons/fi';
import SeverityBadge from '../shared/SeverityBadge';
import { formatDate } from '../../utils/helpers';

export default function FindingHeader({ finding }) {
  return (
    <div className="space-y-3">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1">
          <div className="flex items-center gap-2 mb-2">
            <span className="text-xs font-mono text-text-tertiary dark:text-text-dark-tertiary bg-bg-secondary dark:bg-bg-dark-tertiary px-2 py-0.5 rounded">
              {finding.ruleId}
            </span>
            <SeverityBadge severity={finding.severity} />
          </div>
          <h2 className="text-xl font-bold text-text-primary dark:text-text-dark-primary">{finding.ruleName}</h2>
        </div>
      </div>
      <p className="text-sm text-text-secondary dark:text-text-dark-secondary leading-relaxed">{finding.description}</p>
      <div className="flex flex-wrap gap-4 text-xs text-text-tertiary dark:text-text-dark-tertiary">
        <span className="flex items-center gap-1.5">
          <FiBox size={12} />
          {finding.resourceName}
        </span>
        <span className="flex items-center gap-1.5">
          <FiCalendar size={12} />
          Detected {formatDate(finding.detectedAt)}
        </span>
        <span className="px-2 py-0.5 rounded bg-bg-secondary dark:bg-bg-dark-tertiary">{finding.category}</span>
      </div>
    </div>
  );
}
