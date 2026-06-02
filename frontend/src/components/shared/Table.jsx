import React from 'react';
import EmptyState from './EmptyState';

export default function Table({ columns, data, onRowClick }) {
  if (!data || data.length === 0) {
    return <EmptyState title="No records found" description="Try adjusting your filters." />;
  }

  return (
    <div className="overflow-x-auto custom-scrollbar">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-bg-secondary dark:bg-bg-dark-tertiary">
            {columns.map((col) => (
              <th
                key={col.key}
                className="px-4 py-3 text-left text-xs font-semibold uppercase tracking-wider text-text-secondary dark:text-text-dark-tertiary whitespace-nowrap"
              >
                {col.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-border-light dark:divide-border-dark">
          {data.map((row, idx) => (
            <tr
              key={row.id || idx}
              onClick={() => onRowClick?.(row)}
              className={`transition-colors duration-150 ${onRowClick ? 'cursor-pointer hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary' : ''}`}
            >
              {columns.map((col) => (
                <td key={col.key} className="px-4 py-3 text-text-primary dark:text-text-dark-secondary whitespace-nowrap">
                  {col.render ? col.render(row[col.key], row) : row[col.key]}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
