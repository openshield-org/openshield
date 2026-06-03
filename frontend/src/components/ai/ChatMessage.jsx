import React from 'react';
import { FiCpu, FiUser } from 'react-icons/fi';
import { formatDateTime } from '../../utils/helpers';

export default function ChatMessage({ message }) {
  const isUser = message.role === 'user';
  const hasSources = !isUser && message.sources?.length > 0;

  // Render basic markdown: **bold** and `code` inline, ``` code blocks
  const renderContent = (text) => {
    if (!text) return null;
    const lines = text.split('\n');
    return lines.map((line, i) => {
      if (line.startsWith('```')) return null; // handled below
      return (
        <p key={i} className={line === '' ? 'mt-2' : ''}>
          {parseInline(line)}
        </p>
      );
    });
  };

  const parseInline = (line) => {
    // Handle code blocks as single lines
    const codeBlockMatch = line.match(/^```(?:\w+)?\n?(.*)/);
    if (codeBlockMatch) {
      return (
        <code className="block bg-black/30 dark:bg-black/50 text-green-400 text-xs font-mono px-3 py-1.5 rounded-lg mt-1 overflow-x-auto whitespace-nowrap">
          {codeBlockMatch[1]}
        </code>
      );
    }

    // Split on **bold** and `code`
    const parts = line.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    return parts.map((part, i) => {
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={i}>{part.slice(2, -2)}</strong>;
      }
      if (part.startsWith('`') && part.endsWith('`')) {
        return (
          <code key={i} className={`px-1.5 py-0.5 rounded text-xs font-mono ${isUser ? 'bg-white/20' : 'bg-black/10 dark:bg-black/30'}`}>
            {part.slice(1, -1)}
          </code>
        );
      }
      return part;
    });
  };

  return (
    <div className={`flex gap-3 ${isUser ? 'flex-row-reverse' : ''}`}>
      <div className={`w-7 h-7 rounded-lg flex items-center justify-center flex-shrink-0 ${isUser ? 'bg-brand-primary' : 'bg-bg-secondary dark:bg-bg-dark-tertiary'}`}>
        {isUser
          ? <FiUser size={14} className="text-white" />
          : <FiCpu size={14} className="text-brand-primary" />
        }
      </div>

      <div className={`max-w-[80%] flex flex-col gap-1 ${isUser ? 'items-end' : 'items-start'}`}>
        <div className={`px-3 py-2 rounded-xl text-xs leading-relaxed space-y-0.5 ${
          isUser
            ? 'bg-brand-primary text-white rounded-tr-sm'
            : 'bg-bg-secondary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-secondary rounded-tl-sm'
        }`}>
          {renderContent(message.content)}
        </div>

        {/* Source badges */}
        {hasSources && (
          <div className="flex flex-wrap gap-1.5 px-1">
            {message.sources.map((src, i) => (
              <span
                key={i}
                className="inline-flex items-center gap-1 px-2 py-0.5 text-[10px] font-mono font-semibold rounded-md bg-brand-primary/10 text-brand-primary border border-brand-primary/20"
              >
                {src.id}
                {src.resource && <span className="text-text-tertiary dark:text-text-dark-tertiary font-normal">· {src.resource}</span>}
              </span>
            ))}
          </div>
        )}

        <span className="text-xs text-text-tertiary dark:text-text-dark-tertiary px-1">
          {formatDateTime(message.timestamp)}
        </span>
      </div>
    </div>
  );
}
