import React from 'react';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null;
  const { name, value, payload: p } = payload[0];
  return (
    <div className="bg-bg-primary/95 dark:bg-bg-dark-tertiary/95 backdrop-blur-md border border-border-light dark:border-border-dark rounded-xl p-3 shadow-soft-lg text-xs">
      <span className="font-semibold" style={{ color: p.color }}>{name}</span>
      <span className="text-text-primary dark:text-text-dark-primary ml-2 font-bold">{value}</span>
      <span className="text-text-secondary dark:text-text-dark-tertiary ml-1">findings</span>
    </div>
  );
};

const renderLegend = ({ payload }) => (
  <div className="flex flex-wrap justify-center gap-x-4 gap-y-2 mt-2">
    {payload.map(({ value, color, payload: p }) => (
      <span key={value} className="flex items-center gap-1.5 text-xs text-text-secondary dark:text-text-dark-tertiary">
        <span className="w-2.5 h-2.5 rounded-full flex-shrink-0" style={{ background: color }} />
        {value}
        <span className="font-semibold text-text-primary dark:text-text-dark-primary">{p.value}</span>
      </span>
    ))}
  </div>
);

export default function FindingsDistribution({ data }) {
  const nonZero = data.filter((d) => d.value > 0);

  return (
    <ResponsiveContainer width="100%" height={240}>
      <PieChart>
        <Pie
          data={nonZero}
          cx="50%"
          cy="45%"
          innerRadius={60}
          outerRadius={88}
          paddingAngle={3}
          dataKey="value"
          animationBegin={0}
          animationDuration={800}
        >
          {nonZero.map((entry) => (
            <Cell key={entry.name} fill={entry.color} />
          ))}
        </Pie>
        <Tooltip content={<CustomTooltip />} />
        <Legend content={renderLegend} />
      </PieChart>
    </ResponsiveContainer>
  );
}
