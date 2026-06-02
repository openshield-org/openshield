import React from 'react';
import { FiTrendingUp, FiTrendingDown, FiMinus } from 'react-icons/fi';
import Card from '../shared/Card';

function TrendIcon({ change }) {
  if (change > 0) return <FiTrendingUp size={14} className="text-brand-primary" />;
  if (change < 0) return <FiTrendingDown size={14} className="text-severity-high" />;
  return <FiMinus size={14} className="text-text-tertiary dark:text-text-dark-tertiary" />;
}

export default function HealthMetrics({ metrics }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
      {metrics.map(({ label, value, change }) => (
        <Card key={label} className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wider text-text-secondary dark:text-text-dark-tertiary mb-3">{label}</p>
          <div className="flex items-end justify-between">
            <p className="text-2xl font-bold text-text-primary dark:text-text-dark-primary">{value}</p>
            <div className="flex items-center gap-1 mb-1">
              <TrendIcon change={change} />
              <span className={`text-xs font-medium ${change > 0 ? 'text-brand-primary' : change < 0 ? 'text-severity-high' : 'text-text-tertiary'}`}>
                {change > 0 ? '+' : ''}{change}%
              </span>
            </div>
          </div>
          <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary mt-1">vs last month</p>
        </Card>
      ))}
    </div>
  );
}
