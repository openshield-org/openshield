import React from 'react';
import { FiDatabase, FiServer, FiWifi, FiUser, FiHardDrive, FiKey, FiEye } from 'react-icons/fi';
import RiskBadge from '../shared/RiskBadge';
import EmptyState from '../shared/EmptyState';
import { formatDate } from '../../utils/helpers';

const CATEGORY_ICONS = {
  Storage: FiHardDrive, Compute: FiServer, Network: FiWifi,
  Identity: FiUser, Database: FiDatabase, KeyVault: FiKey, Monitoring: FiEye,
};
const CATEGORY_ORDER = ['Storage', 'Compute', 'Network', 'Identity', 'Database', 'KeyVault', 'Monitoring'];

const HEADERS = ['Resource Name', 'Type', 'Location', 'Resource Group', 'Risk', 'Issues', 'Discovered'];

function IssueBadge({ count }) {
  if (count === 0) {
    return <span className="text-xs text-text-tertiary dark:text-text-dark-tertiary">—</span>;
  }
  return (
    <span className="text-xs text-text-secondary dark:text-text-dark-tertiary tabular-nums">
      {count}
    </span>
  );
}

function TableHead() {
  return (
    <thead>
      <tr className="bg-bg-secondary dark:bg-bg-dark-tertiary">
        {HEADERS.map((h) => (
          <th
            key={h}
            className={`px-4 py-3 text-xs font-semibold uppercase tracking-wider text-text-secondary dark:text-text-dark-tertiary whitespace-nowrap ${h === 'Issues' ? 'text-center' : 'text-left'}`}
          >
            {h}
          </th>
        ))}
      </tr>
    </thead>
  );
}

function TableRow({ resource, issueCount }) {
  return (
    <tr className="hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors duration-150">
      <td className="px-4 py-3 text-sm font-medium text-text-primary dark:text-text-dark-primary whitespace-nowrap">
        {resource.name}
      </td>
      <td className="px-4 py-3 text-xs text-text-secondary dark:text-text-dark-tertiary whitespace-nowrap">
        {resource.type?.split('/').pop()}
      </td>
      <td className="px-4 py-3 text-xs text-text-secondary dark:text-text-dark-tertiary">
        {resource.location}
      </td>
      <td className="px-4 py-3 text-xs text-text-secondary dark:text-text-dark-tertiary font-mono">
        {resource.resourceGroup}
      </td>
      <td className="px-4 py-3">
        <RiskBadge risk={resource.risk} />
      </td>
      <td className="px-4 py-3 text-center">
        <IssueBadge count={issueCount} />
      </td>
      <td className="px-4 py-3 text-xs text-text-secondary dark:text-text-dark-tertiary whitespace-nowrap">
        {formatDate(resource.discoveredAt)}
      </td>
    </tr>
  );
}

function FlatTable({ resources, issueCounts }) {
  if (!resources.length) return <EmptyState title="No resources found" description="Try adjusting your filters." />;
  return (
    <div className="overflow-x-auto custom-scrollbar">
      <table className="w-full text-sm">
        <TableHead />
        <tbody className="divide-y divide-border-light dark:divide-border-dark">
          {resources.map((r) => (
            <TableRow key={r.id} resource={r} issueCount={issueCounts[r.name] ?? 0} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function GroupedTable({ resources, issueCounts }) {
  const grouped = CATEGORY_ORDER.reduce((acc, cat) => {
    const items = resources.filter((r) => r.category === cat);
    if (items.length) acc[cat] = items;
    return acc;
  }, {});

  if (!Object.keys(grouped).length) {
    return <EmptyState title="No resources found" description="Try adjusting your filters." />;
  }

  return (
    <div className="space-y-4">
      {Object.entries(grouped).map(([cat, items]) => {
        const Icon = CATEGORY_ICONS[cat] || FiDatabase;
        return (
          <div key={cat} className="rounded-xl border border-border-light dark:border-border-dark overflow-hidden">
            <div className="flex items-center gap-2 px-4 py-2.5 bg-bg-secondary dark:bg-bg-dark-tertiary border-b border-border-light dark:border-border-dark">
              <div className="w-6 h-6 rounded-md bg-brand-primary/10 flex items-center justify-center">
                <Icon size={12} className="text-brand-primary" />
              </div>
              <span className="text-xs font-semibold text-text-primary dark:text-text-dark-primary">{cat}</span>
              <span className="ml-1 text-xs text-text-tertiary dark:text-text-dark-tertiary">({items.length})</span>
            </div>
            <div className="overflow-x-auto custom-scrollbar">
              <table className="w-full text-sm">
                <TableHead />
                <tbody className="divide-y divide-border-light dark:divide-border-dark">
                  {items.map((r) => (
                    <TableRow key={r.id} resource={r} issueCount={issueCounts[r.name] ?? 0} />
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default function ResourceTable({ resources, issueCounts = {}, groupByCategory }) {
  return groupByCategory
    ? <GroupedTable resources={resources} issueCounts={issueCounts} />
    : <FlatTable resources={resources} issueCounts={issueCounts} />;
}
