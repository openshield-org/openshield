import { NavLink } from 'react-router';
import {
  FiActivity, FiSearch, FiTarget, FiZap,
  FiShield, FiGitBranch, FiCpu, FiSun, FiMoon, FiX,
} from 'react-icons/fi';
import { useDarkMode } from '../../contexts/DarkModeContext';
import { useI18n } from '../../i18n/I18nState';
import Logo from '../shared/Logo';

const navItems = [
  { path: '/monitoring', key: 'monitoring', Icon: FiActivity  },
  { path: '/discovery', key: 'discovery', Icon: FiSearch    },
  { path: '/prioritization', key: 'prioritization', Icon: FiTarget    },
  { path: '/scan', key: 'scan', Icon: FiZap       },
  { path: '/compliance', key: 'compliance', Icon: FiShield    },
  { path: '/drift', key: 'drift', Icon: FiGitBranch },
  { path: '/ai', key: 'ai', Icon: FiCpu       },
];

export default function Sidebar({ isOpen, onClose }) {
  const { isDark, toggle } = useDarkMode();
  const { t } = useI18n();

  return (
    <>
      {/* ── Desktop sidebar (always visible on lg+) ── */}
      <aside aria-label={t('nav.primary')} className="hidden lg:flex fixed left-0 top-0 h-full w-20 flex-col items-center py-4 bg-bg-primary dark:bg-bg-dark-secondary border-r border-border-light dark:border-border-dark z-50">
        <div className="mb-6">
          <Logo size={36} />
        </div>

        <nav aria-label={t('nav.primary')} className="flex-1 flex flex-col items-center gap-1 w-full px-2">
          {navItems.map(({ path, key, Icon }) => (
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
                    <Icon size={16} aria-hidden="true" />
                  </div>
                  <span className="text-xs font-medium leading-none">{t(`nav.${key}`)}</span>
                </>
              )}
            </NavLink>
          ))}
        </nav>

        <button
          onClick={toggle}
          className="w-10 h-10 rounded-lg flex items-center justify-center text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-all duration-200"
          aria-label={t('theme.toggle')}
        >
          {isDark ? <FiSun size={16} /> : <FiMoon size={16} />}
        </button>
      </aside>

      {/* ── Mobile drawer (slides in from left on < lg) ── */}
      <aside
        aria-label={t('nav.primary')}
        aria-modal="true"
        role="dialog"
        inert={isOpen ? undefined : ''}
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
            aria-label={t('menu.close')}
          >
            <FiX size={18} />
          </button>
        </div>

        {/* Drawer nav */}
        <nav aria-label={t('nav.primary')} className="flex-1 overflow-y-auto py-3 px-3">
          {navItems.map(({ path, key, Icon }) => (
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
                    <Icon size={16} aria-hidden="true" />
                  </div>
                  <span className="text-sm font-medium">{t(`nav.${key}`)}</span>
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
            {isDark ? <FiSun size={16} aria-hidden="true" /> : <FiMoon size={16} aria-hidden="true" />}
            <span className="text-sm font-medium">{isDark ? t('theme.light') : t('theme.dark')}</span>
          </button>
        </div>
      </aside>
    </>
  );
}
