import React, { useState } from 'react';
import { FiDownload, FiChevronDown } from 'react-icons/fi';
import { downloadJSON, downloadCSV } from '../../utils/helpers';

export default function ExportButton({ controls, framework }) {
  const [open, setOpen] = useState(false);

  const exportJSON = () => {
    downloadJSON(controls, `compliance-${framework?.id || 'all'}.json`);
    setOpen(false);
  };

  const exportCSV = () => {
    const headers = ['id', 'name', 'framework', 'status', 'severity', 'category', 'resources'];
    downloadCSV(controls, headers, `compliance-${framework?.id || 'all'}.csv`);
    setOpen(false);
  };

  return (
    <div className="relative">
      <button
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary text-text-primary dark:text-text-dark-primary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-all duration-200"
      >
        <FiDownload size={14} /> Export <FiChevronDown size={14} />
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 w-36 bg-bg-primary dark:bg-bg-dark-secondary border border-border-light dark:border-border-dark rounded-xl shadow-soft-lg z-10 overflow-hidden">
          <button onClick={exportJSON} className="w-full text-left px-4 py-2.5 text-sm text-text-primary dark:text-text-dark-secondary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors">
            Export JSON
          </button>
          <button onClick={exportCSV} className="w-full text-left px-4 py-2.5 text-sm text-text-primary dark:text-text-dark-secondary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors">
            Export CSV
          </button>
        </div>
      )}
    </div>
  );
}
