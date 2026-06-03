import React, { useEffect, useState } from 'react';
import { api } from '../utils/api';
import FrameworkCards from '../components/compliance/FrameworkCards';
import ComplianceTable from '../components/compliance/ComplianceTable';
import ComparisonChart from '../components/compliance/ComparisonChart';
import ExportButton from '../components/compliance/ExportButton';
import Card from '../components/shared/Card';
import Loader from '../components/shared/Loader';

export default function Compliance() {
  const [data, setData] = useState(null);
  const [selectedFw, setSelectedFw] = useState(null);
  const [statusFilter, setStatusFilter] = useState('All');

  useEffect(() => {
    api.getCompliance().then((d) => {
      setData(d);
      setSelectedFw(d.frameworks[0]);
    });
  }, []);

  if (!data) return <Loader rows={8} />;

  const filteredControls = data.controls.filter((c) => {
    if (selectedFw && c.framework !== selectedFw.name) return false;
    if (statusFilter !== 'All' && c.status !== statusFilter) return false;
    return true;
  });

  return (
    <div className="space-y-6">
      <FrameworkCards frameworks={data.frameworks} selected={selectedFw} onSelect={setSelectedFw} />

      <Card>
        <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary mb-4">Framework Score Trends</h2>
        <ComparisonChart trend={data.trend} />
      </Card>

      <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary overflow-hidden">
        <div className="p-4 flex items-center justify-between border-b border-border-light dark:border-border-dark">
          <div className="flex items-center gap-4">
            <h2 className="text-base font-semibold text-text-primary dark:text-text-dark-primary">
              Controls <span className="text-text-tertiary font-normal text-sm">({filteredControls.length})</span>
            </h2>
            <div className="flex gap-1">
              {['All', 'PASS', 'FAIL'].map((s) => (
                <button
                  key={s}
                  onClick={() => setStatusFilter(s)}
                  className={`px-3 py-1 text-xs rounded-lg font-medium transition-all duration-200 ${
                    statusFilter === s
                      ? 'bg-brand-primary text-white'
                      : 'text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary'
                  }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
          <ExportButton controls={filteredControls} framework={selectedFw} />
        </div>
        <ComplianceTable controls={filteredControls} />
      </div>
    </div>
  );
}
