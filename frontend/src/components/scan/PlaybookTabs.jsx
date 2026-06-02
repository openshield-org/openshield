import React, { useState } from 'react';
import PortalSteps from './PortalSteps';
import CLICommands from './CLICommands';
import ValidationSteps from './ValidationSteps';

const TABS = [
  { key: 'portal', label: 'Portal Steps' },
  { key: 'cli', label: 'CLI Commands' },
  { key: 'validation', label: 'Validation' },
];

export default function PlaybookTabs({ finding }) {
  const [active, setActive] = useState('portal');

  return (
    <div>
      <div className="flex border-b border-border-light dark:border-border-dark mb-6">
        {TABS.map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setActive(key)}
            className={`px-4 py-3 text-sm font-medium transition-all duration-200 border-b-2 -mb-px ${
              active === key
                ? 'border-brand-primary text-brand-primary'
                : 'border-transparent text-text-secondary dark:text-text-dark-tertiary hover:text-text-primary dark:hover:text-text-dark-primary'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {active === 'portal' && <PortalSteps steps={finding.portalSteps} />}
      {active === 'cli' && <CLICommands commands={finding.cliCommands} />}
      {active === 'validation' && <ValidationSteps steps={finding.validationSteps} />}
    </div>
  );
}
