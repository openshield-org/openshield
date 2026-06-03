import React from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from 'recharts';

const CustomTooltip = ({ active, payload, label }) => {
  if (!active || !payload?.length) return null;
  return (
    <div className="bg-bg-primary/95 dark:bg-bg-dark-tertiary/95 backdrop-blur-md border border-border-light dark:border-border-dark rounded-xl p-3 shadow-soft-lg text-sm">
      <p className="font-semibold text-text-primary dark:text-text-dark-primary mb-1">{label}</p>
      {payload.map((p) => (
        <p key={p.name} style={{ color: p.color }} className="text-xs">
          {p.name}: <span className="font-semibold">{p.value}</span>
        </p>
      ))}
    </div>
  );
};

export default function TrendChart({ trend }) {
  return (
    <ResponsiveContainer width="100%" height={220}>
      <AreaChart data={trend} margin={{ top: 5, right: 5, bottom: 0, left: -10 }}>
        <defs>
          <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#10b981" stopOpacity={0.2} />
            <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
          </linearGradient>
          <linearGradient id="targetGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.15} />
            <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" strokeOpacity={0.3} />
        <XAxis dataKey="month" tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} axisLine={false} tickLine={false} domain={[0, 100]} />
        <Tooltip content={<CustomTooltip />} />
        <Legend wrapperStyle={{ fontSize: 12, paddingTop: 8 }} />
        <Area
          type="monotone"
          dataKey="score"
          name="Score"
          stroke="#10b981"
          strokeWidth={2}
          fill="url(#scoreGrad)"
          animationDuration={800}
        />
        <Area
          type="monotone"
          dataKey="target"
          name="Target"
          stroke="#3b82f6"
          strokeWidth={2}
          strokeDasharray="4 4"
          fill="url(#targetGrad)"
          animationDuration={800}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
