import React from 'react';

export default function Card({ children, className = '', onClick }) {
  return (
    <div
      className={`rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary p-6 shadow-soft hover:shadow-soft-lg transition-all duration-200 ${onClick ? 'cursor-pointer' : ''} ${className}`}
      onClick={onClick}
    >
      {children}
    </div>
  );
}
