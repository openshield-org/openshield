import React from 'react';

const variants = {
  primary: 'bg-brand-primary hover:bg-brand-secondary text-white',
  secondary: 'bg-bg-secondary dark:bg-bg-dark-tertiary hover:bg-bg-tertiary dark:hover:bg-border-dark text-text-primary dark:text-text-dark-primary border border-border-light dark:border-border-dark',
  danger: 'bg-severity-high hover:opacity-90 text-white',
  ghost: 'text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary',
};

const sizes = {
  sm: 'px-3 py-1.5 text-xs',
  md: 'px-4 py-2 text-sm',
  lg: 'px-6 py-3 text-base',
};

export default function Button({ children, variant = 'primary', size = 'md', className = '', disabled, onClick, type = 'button' }) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center gap-2 rounded-lg font-medium transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed ${variants[variant]} ${sizes[size]} ${className}`}
    >
      {children}
    </button>
  );
}
