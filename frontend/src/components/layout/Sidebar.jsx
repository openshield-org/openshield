import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  FiActivity, FiSearch, FiTarget, FiZap,
  FiShield, FiGitBranch, FiCpu, FiSun, FiMoon, FiX,
} from 'react-icons/fi';
import { useDarkMode } from '../../contexts/DarkModeContext';
import Logo from '../shared/Logo';

const navItems = [
  { path: '/monitoring',     label: 'Monitor',    Icon: FiActivity  },
  { path: '/discovery',      label: 'Discover',   Icon: FiSearch    },
  { path: '/prioritization', label: 'Prioritize', Icon: FiTarget    },
  { path: '/scan',           label: 'Scan',       Icon: FiZap       },
  { path: '/compliance',     label: 'Comply',     Icon: FiShield    },
  { path: '/drift',          label: 'Drift',      Icon: FiGitBranch },
  { path: '/ai',             label: 'AI',         Icon: FiCpu       },
];

export default function Sidebar({ isOpen, onClose }) {
  const { isDark, toggle } = useDarkMode();

  return (
    <>
      {/* ── Desktop sidebar (always visible on lg+) ── */}
      <aside className="hidden lg:flex fixed left-0 top-0 h-full w-20 flex-col items-center py-4 bg-bg-primary dark:bg-bg-dark-secondary border-r border-border-light dark:border-border-dark z-50">
        <div className="mb-6">
          <Logo size={36} />
        </div>

        <nav className="flex-1 flex flex-col items-center gap-1 w-full px-2">
          {navItems.map(({ path, label, Icon }) => (
            <NavLink
              key={path}
              to={path}
              className={({ isActive }) =>
                `w-full flex flex-col items-center gap-1 py-2.5 px-1.5 rounded-lg transition-all duration-200 ${
                  isActive
                    ? 'bg-brand-primary/10 text-brand-primary'
                    : 'text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary hover:text-text-primary dark:hover:text-text-dark-primary'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <div className={`p-1.5 rounded-lg transition-all duration-200 ${isActive ? 'bg-brand-primary text-white' : ''}`}>
                    <Icon size={16} />
                  </div>
                  <span className="text-xs font-medium leading-none">{label}</span>
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <button
          onClick={toggle}
          className="w-10 h-10 rounded-lg flex items-center justify-center text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-all duration-200"
          aria-label="Toggle dark mode"
        >
          {isDark ? <FiSun size={16} /> : <FiMoon size={16} />}
        </button>
      </aside>

      {/* ── Mobile drawer (slides in from left on < lg) ── */}
      <aside
        className={`lg:hidden fixed left-0 top-0 h-full w-64 flex flex-col bg-bg-primary dark:bg-bg-dark-secondary border-r border-border-light dark:border-border-dark z-50 transform transition-transform duration-300 ease-in-out ${
          isOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        {/* Drawer header */}
        <div className="flex items-center justify-between px-4 py-4 border-b border-border-light dark:border-border-dark">
          <div className="flex items-center gap-3">
            <Logo size={34} showWordmark />
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-all"
            aria-label="Close menu"
          >
            <FiX size={18} />
          </button>
        </div>

        {/* Drawer nav */}
        <nav className="flex-1 overflow-y-auto py-3 px-3">
          {navItems.map(({ path, label, Icon }) => (
            <NavLink
              key={path}
              to={path}
              onClick={onClose}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-3 rounded-xl mb-1 transition-all duration-200 ${
                  isActive
                    ? 'bg-brand-primary/10 text-brand-primary'
                    : 'text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary hover:text-text-primary dark:hover:text-text-dark-primary'
                }`
              }
            >
              {({ isActive }) => (
                <>
                  <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 transition-all ${isActive ? 'bg-brand-primary text-white' : ''}`}>
                    <Icon size={16} />
                  </div>
                  <span className="text-sm font-medium">{label}</span>
                </>
              )}
            </NavLink>
          ))}
        </nav>

        {/* Drawer footer */}
        <div className="px-3 py-4 border-t border-border-light dark:border-border-dark">
          <button
            onClick={toggle}
            className="flex items-center gap-3 w-full px-3 py-3 rounded-xl text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-all"
          >
            {isDark ? <FiSun size={16} /> : <FiMoon size={16} />}
            <span className="text-sm font-medium">{isDark ? 'Light mode' : 'Dark mode'}</span>
          </button>
        </div>
      </aside>
    </>
  );
}
