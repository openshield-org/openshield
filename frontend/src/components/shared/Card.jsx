
export default function Card({ children, className = '', onClick }) {
  const classes = `rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary p-6 shadow-soft hover:shadow-soft-lg transition-all duration-200 ${onClick ? 'cursor-pointer' : ''} ${className}`;
  if (onClick) {
    return (
      <button type="button" className={`${classes} text-left`} onClick={onClick}>
        {children}
      </button>
    );
  }
  return (
    <div className={classes}>
      {children}
    </div>
  );
}
