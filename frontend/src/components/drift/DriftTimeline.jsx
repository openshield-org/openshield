import React from 'react';
import DriftEventCard from './DriftEventCard';
import EmptyState from '../shared/EmptyState';
import { FiGitBranch } from 'react-icons/fi';

export default function DriftTimeline({ events }) {
  if (!events.length) {
    return <EmptyState icon={FiGitBranch} title="No drift detected" description="No configuration changes match the current filters." />;
  }

  return (
    <div className="space-y-3">
      {events.map((event) => (
        <DriftEventCard key={event.id} event={event} />
      ))}
    </div>
  );
}
