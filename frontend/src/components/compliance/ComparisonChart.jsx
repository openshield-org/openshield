import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const COLORS = {
  'CIS Azure': '#3b82f6',
  'NIST SP 800-53': '#8b5cf6',
  'ISO 27001': '#10b981',
  'SOC 2 Type II': '#f59e0b',
};

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-bg-primary/95 dark:bg-bg-dark-tertiary/95 backdrop-blur-md border border-border-light dark:border-border-dark rounded-xl p-3 shadow-soft-lg text-xs">
      <p className="font-semibold text-text-primary dark:text-text-dark-primary mb-2">{label}</p>
      {payload.map((p) => (
        <p key={p.name} className="flex justify-between gap-4" style={{ color: p.color }}>
          <span>{p.name}</span>
          <span className="font-bold">{p.value}%</span>
        </p>
      ))}
    </div>
  );
};

export default function ComparisonChart({ trend }) {
  const frameworks = Object.keys(trend[0] || {}).filter((k) => k !== 'month');

  return (
    <ResponsiveContainer width="100%" height={220}>
      <LineChart data={trend} margin={{ top: 5, right: 5, bottom: 0, left: -10 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" strokeOpacity={0.3} />
        <XAxis dataKey="month" tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} domain={[40, 100]} />
        <Tooltip content={<CustomTooltip />} />
        <Legend wrapperStyle={{ fontSize: 11, paddingTop: 8 }} />
        {frameworks.map((fw) => (
          <Line
            key={fw}
            type="monotone"
            dataKey={fw}
            stroke={COLORS[fw] || '#6b7280'}
            strokeWidth={2}
            dot={{ r: 3, fill: COLORS[fw] || '#6b7280' }}
            animationDuration={800}
          />
        ))}
      </LineChart>
    </ResponsiveContainer>
  );
}
