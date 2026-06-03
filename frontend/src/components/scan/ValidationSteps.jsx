import React from 'react';
import { FiCheckCircle } from 'react-icons/fi';

export default function ValidationSteps({ steps }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-text-secondary dark:text-text-dark-secondary">
        After applying the fix, verify it was successful:
      </p>
      {steps.map((step, i) => (
        <div key={i} className="flex gap-3 p-3 rounded-xl bg-green-50 dark:bg-green-900/10 border border-green-100 dark:border-green-900/20">
          <FiCheckCircle size={16} className="text-brand-primary flex-shrink-0 mt-0.5" />
          <p className="text-sm text-text-primary dark:text-text-dark-secondary">{step}</p>
        </div>
      ))}
    </div>
  );
}
