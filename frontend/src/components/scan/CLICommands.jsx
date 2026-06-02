import React, { useState } from 'react';
import { FiCopy, FiCheck } from 'react-icons/fi';

function CodeBlock({ command }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="group relative bg-bg-dark-primary dark:bg-black rounded-xl p-4 font-mono text-sm">
      <code className="text-green-400 whitespace-pre-wrap break-all">{command}</code>
      <button
        onClick={copy}
        className="absolute top-3 right-3 opacity-0 group-hover:opacity-100 transition-opacity p-1.5 rounded-lg bg-bg-dark-tertiary hover:bg-border-dark text-text-dark-tertiary hover:text-text-dark-primary"
        aria-label="Copy command"
      >
        {copied ? <FiCheck size={14} className="text-brand-primary" /> : <FiCopy size={14} />}
      </button>
    </div>
  );
}

export default function CLICommands({ commands }) {
  return (
    <div className="space-y-3">
      <p className="text-sm text-text-secondary dark:text-text-dark-secondary">
        Run these commands in your Azure CLI session to remediate this finding:
      </p>
      {commands.map((cmd, i) => (
        <CodeBlock key={i} command={cmd} />
      ))}
    </div>
  );
}
