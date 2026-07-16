import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Header from './Header';
import { useI18n } from '../../i18n/I18nState';

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { t } = useI18n();

  return (
    <div className="min-h-screen bg-bg-secondary dark:bg-bg-dark-primary transition-colors duration-300">
      <a href="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[200] focus:bg-bg-primary focus:text-text-primary focus:px-4 focus:py-2 focus:rounded-lg">
        {t('skip.content')}
      </a>
      {/* Mobile overlay */}
      {sidebarOpen && (
        <button
          type="button"
          aria-label={t('menu.close')}
          className="fixed inset-0 bg-black/50 z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <Sidebar isOpen={sidebarOpen} onClose={() => setSidebarOpen(false)} />

      <div className="lg:ml-20 flex flex-col min-h-screen">
        <Header onMenuToggle={() => setSidebarOpen((v) => !v)} />
        <main id="main-content" tabIndex="-1" className="flex-1 p-4 md:p-6 relative">
          <div className="absolute inset-0 dot-pattern pointer-events-none" />
          <div className="relative z-10">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
