import React from 'react';
import { FiLoader } from 'react-icons/fi';

export default function ContextBubble({ thinking }) {
  if (!thinking) return null;

  return (
    <div className="flex gap-3">
      <div className="w-8 h-8 rounded-lg bg-bg-secondary dark:bg-bg-dark-tertiary flex items-center justify-center flex-shrink-0">
        <FiLoader size={14} className="text-brand-primary animate-spin" />
      </div>
      <div className="px-4 py-3 rounded-2xl rounded-tl-sm bg-bg-secondary dark:bg-bg-dark-tertiary">
        <div className="flex gap-1.5 items-center">
          <span className="w-2 h-2 rounded-full bg-brand-primary animate-bounce" style={{ animationDelay: '0ms' }} />
          <span className="w-2 h-2 rounded-full bg-brand-primary animate-bounce" style={{ animationDelay: '150ms' }} />
          <span className="w-2 h-2 rounded-full bg-brand-primary animate-bounce" style={{ animationDelay: '300ms' }} />
        </div>
      </div>
    </div>
  );
}
