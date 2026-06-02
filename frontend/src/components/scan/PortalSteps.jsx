import React from 'react';

export default function PortalSteps({ steps }) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-text-secondary dark:text-text-dark-secondary">
        Follow these steps in the Azure Portal to apply the fix:
      </p>
      <div className="space-y-3">
        {steps.map((step, i) => (
          <div key={i} className="flex gap-4">
            <div className="flex-shrink-0 w-7 h-7 rounded-full bg-brand-primary text-white text-sm font-bold flex items-center justify-center">
              {i + 1}
            </div>
            <div className="flex-1 pt-0.5">
              <p className="text-sm text-text-primary dark:text-text-dark-secondary">{step}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
