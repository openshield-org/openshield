import React, { useState } from 'react';
import { FiSend } from 'react-icons/fi';

export default function ChatInput({ onSend, disabled }) {
  const [value, setValue] = useState('');

  const submit = () => {
    if (!value.trim() || disabled) return;
    onSend(value.trim());
    setValue('');
  };

  const onKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      submit();
    }
  };

  return (
    <div className="flex gap-2 p-4 border-t border-border-light dark:border-border-dark">
      <textarea
        value={value}
        onChange={(e) => setValue(e.target.value)}
        onKeyDown={onKey}
        placeholder="Ask about your security findings..."
        rows={2}
        className="flex-1 resize-none px-4 py-3 text-sm rounded-xl border border-border-light dark:border-border-dark bg-bg-secondary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary placeholder:text-text-tertiary dark:placeholder:text-text-dark-tertiary focus:outline-none focus:ring-1 focus:ring-brand-primary custom-scrollbar"
      />
      <button
        onClick={submit}
        disabled={!value.trim() || disabled}
        className="w-10 h-10 self-end flex items-center justify-center rounded-xl bg-brand-primary hover:bg-brand-secondary disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-200 flex-shrink-0"
      >
        <FiSend size={16} className="text-white" />
      </button>
    </div>
  );
}
