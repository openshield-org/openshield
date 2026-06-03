import React from 'react';

function Skeleton({ className }) {
  return <div className={`animate-pulse rounded bg-bg-secondary dark:bg-bg-dark-tertiary ${className}`} />;
}

export default function Loader({ rows = 5 }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center gap-4">
          <Skeleton className="w-8 h-8 rounded-lg flex-shrink-0" />
          <div className="flex-1 space-y-2">
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-3 w-1/2" />
          </div>
          <Skeleton className="w-16 h-6 rounded-lg" />
        </div>
      ))}
    </div>
  );
}

export function CardLoader() {
  return (
    <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary p-6 space-y-4">
      <Skeleton className="h-5 w-1/3" />
      <Skeleton className="h-10 w-1/2" />
      <Skeleton className="h-3 w-2/3" />
    </div>
  );
}
