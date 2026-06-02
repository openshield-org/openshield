import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from 'recharts';

const COLORS = { HIGH: '#ef4444', MEDIUM: '#f97316', LOW: '#10b981' };

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((s, p) => s + p.value, 0);
  return (
    <div className="bg-bg-primary/95 dark:bg-bg-dark-tertiary/95 backdrop-blur-md border border-border-light dark:border-border-dark rounded-xl p-3 shadow-soft-lg text-xs">
      <p className="font-semibold text-text-primary dark:text-text-dark-primary mb-2">{label}</p>
      {payload.map((p) => (
        <p key={p.name} className="flex justify-between gap-6" style={{ color: p.fill }}>
          <span>{p.name}</span>
          <span className="font-bold">{p.value}</span>
        </p>
      ))}
      <p className="border-t border-border-light dark:border-border-dark mt-1.5 pt-1.5 text-text-secondary dark:text-text-dark-tertiary flex justify-between">
        <span>Total</span><span className="font-bold text-text-primary dark:text-text-dark-primary">{total}</span>
      </p>
    </div>
  );
};

export default function ResourceGroupChart({ data }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <BarChart data={data} margin={{ top: 5, right: 5, bottom: 0, left: -10 }} barCategoryGap="35%">
        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" strokeOpacity={0.3} />
        <XAxis dataKey="group" tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} />
        <Tooltip content={<CustomTooltip />} />
        <Legend wrapperStyle={{ fontSize: 12, paddingTop: 8 }} />
        <Bar dataKey="HIGH"   name="High"   stackId="a" fill={COLORS.HIGH}   radius={[0, 0, 0, 0]} animationDuration={800} />
        <Bar dataKey="MEDIUM" name="Medium" stackId="a" fill={COLORS.MEDIUM} radius={[0, 0, 0, 0]} animationDuration={800} />
        <Bar dataKey="LOW"    name="Low"    stackId="a" fill={COLORS.LOW}    radius={[4, 4, 0, 0]} animationDuration={800} />
      </BarChart>
    </ResponsiveContainer>
  );
}
