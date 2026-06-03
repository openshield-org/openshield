import React, { useEffect, useState } from 'react';
import { api } from '../utils/api';
import monitoringMock from '../mockData/monitoring.json';
import ScoreGauge from '../components/monitoring/ScoreGauge';
import TrendChart from '../components/monitoring/TrendChart';
import StatCards from '../components/monitoring/StatCards';
import FindingsDistribution from '../components/monitoring/FindingsDistribution';
import ResourceGroupChart from '../components/monitoring/ResourceGroupChart';
import Card from '../components/shared/Card';
import Loader, { CardLoader } from '../components/shared/Loader';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

// Build per-resource-group breakdown from a flat findings array
function buildRgGroups(findings) {
  const groups = {};
  findings.forEach((f) => {
    const rg = f.resourceGroup || 'unknown';
    if (!groups[rg]) groups[rg] = { group: rg, HIGH: 0, MEDIUM: 0, LOW: 0 };
    const sev = (f.severity || '').toUpperCase();
    if (sev === 'HIGH' || sev === 'MEDIUM' || sev === 'LOW') groups[rg][sev]++;
  });
  return Object.values(groups).sort((a, b) => (b.HIGH + b.MEDIUM + b.LOW) - (a.HIGH + a.MEDIUM + a.LOW));
}

export default function Monitoring() {
  const [data, setData] = useState(null);

  useEffect(() => {
    if (api.isDemoMode()) {
      // Demo mode: use static mock data
      api.getMonitoring().then(setData);
      return;
    }

    // Live mode: fetch real score + findings, overlay onto mock structure
    // (trend and categoryScores stay from mock — no backend endpoint for those yet)
    Promise.all([api.getScore(), api.getFindings()])
      .then(([scoreData, findings]) => {
        const high   = findings.filter((f) => (f.severity || '').toUpperCase() === 'HIGH').length;
        const medium = findings.filter((f) => (f.severity || '').toUpperCase() === 'MEDIUM').length;
        const low    = findings.filter((f) => (f.severity || '').toUpperCase() === 'LOW').length;
        const total  = findings.length;

        setData({
          ...monitoringMock,                  // keeps trend, categoryScores from mock
          score:    scoreData.score    ?? scoreData,
          maxScore: scoreData.max_score ?? 100,
          stats: {
            totalFindings: total,
            criticalIssues: high,
            mediumRisk:     medium,
            lowPriority:    low,
          },
          findingsDistribution: [
            { name: 'High',   value: high,   color: '#ef4444' },
            { name: 'Medium', value: medium, color: '#f97316' },
            { name: 'Low',    value: low,    color: '#10b981' },
          ],
          findingsByResourceGroup: buildRgGroups(findings),
        });
      })
      .catch(() => {
        // Backend unreachable — fall back to mock gracefully
        api.getMonitoring().then(setData);
      });
  }, []);

  if (!data) return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">{[...Array(4)].map((_, i) => <CardLoader key={i} />)}</div>
      <Loader rows={6} />
    </div>
  );

  const categoryColors = ['#10b981', '#3b82f6', '#ef4444', '#f59e0b', '#8b5cf6', '#f97316', '#06b6d4'];

  return (
    <div className="space-y-6">
      <StatCards stats={data.stats} />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card className="flex items-center justify-center">
          <ScoreGauge score={data.score} maxScore={data.maxScore} />
        </Card>

        <Card className="lg:col-span-2">
          <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-4">Score Trend (6 months)</h2>
          <TrendChart trend={data.trend} />
        </Card>
      </div>

      <Card>
        <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-4">Security Score by Category</h2>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={data.categoryScores} margin={{ top: 0, right: 0, bottom: 0, left: -10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" strokeOpacity={0.3} />
            <XAxis dataKey="category" tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} axisLine={false} tickLine={false} domain={[0, 100]} />
            <Tooltip
              contentStyle={{ background: 'rgba(255,255,255,0.95)', border: '1px solid #e5e7eb', borderRadius: 12, fontSize: 12 }}
              formatter={(v) => [`${v}%`, 'Score']}
            />
            <Bar dataKey="score" radius={[4, 4, 0, 0]} animationDuration={800}>
              {data.categoryScores.map((_, i) => <Cell key={i} fill={categoryColors[i % categoryColors.length]} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-1">Findings Distribution</h2>
          <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mb-2">Breakdown by severity across all resources</p>
          <FindingsDistribution data={data.findingsDistribution} />
        </Card>

        <Card>
          <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-1">Issues by Resource Group</h2>
          <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mb-4">Count and severity of findings per resource group</p>
          <ResourceGroupChart data={data.findingsByResourceGroup} />
        </Card>
      </div>
    </div>
  );
}
