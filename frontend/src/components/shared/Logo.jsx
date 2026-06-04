import React from 'react';

// Shield-Lock mark: filled rounded shield with a solid keyhole cutout.
// Usage:
//   <Logo />                       icon mark only, 32px
//   <Logo size={40} />             icon mark only, 40px
//   <Logo showWordmark />           icon + "OpenShield" wordmark, default size
//   <Logo size={28} showWordmark /> smaller icon + wordmark
function ShieldLockMark({ size = 32, uid = 'logo', className = '' }) {
  const gradId = `sg-${uid}`;
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      aria-label="OpenShield"
      className={className}
    >
      <defs>
        <linearGradient id={gradId} x1="4" y1="2" x2="28" y2="30" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#6366f1" />
          <stop offset="50%" stopColor="#7c3aed" />
          <stop offset="100%" stopColor="#06b6d4" />
        </linearGradient>
      </defs>
      {/* Shield body */}
      <path
        d="M16 2L4 7v8c0 7 5.1 13.5 12 15.2C22.9 28.5 28 22 28 15V7L16 2z"
        fill={`url(#${gradId})`}
      />
      {/* Lock body */}
      <rect x="12" y="15" width="8" height="7" rx="1.5" fill="white" />
      {/* Lock shackle */}
      <path
        d="M13.5 15v-2a2.5 2.5 0 0 1 5 0v2"
        stroke="white"
        strokeWidth="1.6"
        strokeLinecap="round"
        fill="none"
      />
      {/* Keyhole dot */}
      <circle cx="16" cy="18.2" r="1.2" fill={`url(#${gradId})`} />
    </svg>
  );
}

export default function Logo({ size = 32, showWordmark = false, className = '' }) {
  if (!showWordmark) return <ShieldLockMark size={size} className={className} />;

  return (
    <div className={`flex items-center gap-2.5 ${className}`}>
      <ShieldLockMark size={size} />
      <span
        className="font-bold text-text-primary dark:text-text-dark-primary leading-none tracking-tight"
        style={{ fontSize: Math.round(size * 0.56) }}
      >
        OpenShield
      </span>
    </div>
  );
}
