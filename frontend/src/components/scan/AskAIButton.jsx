import React from 'react';
import { FiCpu } from 'react-icons/fi';
import { useNavigate } from 'react-router-dom';

export default function AskAIButton({ finding }) {
  const navigate = useNavigate();

  return (
    <button
      onClick={() => navigate('/ai', { state: { finding } })}
      className="w-full flex items-center gap-3 p-4 rounded-xl border border-brand-primary/30 bg-brand-primary/5 hover:bg-brand-primary/10 transition-all duration-200 group"
    >
      <div className="w-9 h-9 rounded-lg bg-brand-primary flex items-center justify-center flex-shrink-0">
        <FiCpu size={16} className="text-white" />
      </div>
      <div className="text-left">
        <p className="text-sm font-semibold text-brand-primary">Ask AI Assistant</p>
        <p className="text-xs text-text-secondary dark:text-text-dark-tertiary">
          {finding ? `Discuss ${finding.ruleId} — ${finding.ruleName}` : 'Ask about your security findings'}
        </p>
      </div>
    </button>
  );
}
