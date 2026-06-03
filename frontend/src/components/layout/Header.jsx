import React, { useEffect, useRef, useState } from 'react';
import { useLocation } from 'react-router-dom';
import {
  FiMenu, FiAlertTriangle, FiX,
  FiLoader, FiZap, FiCheckCircle, FiAlertCircle, FiClock,
} from 'react-icons/fi';
import { api } from '../../utils/api';

const PAGE_TITLES = {
  '/monitoring':     { title: 'Security Monitoring',  subtitle: 'Overall health score and trends' },
  '/discovery':      { title: 'Resource Discovery',   subtitle: 'All resources across your Azure environment' },
  '/prioritization': { title: 'Risk Prioritization',  subtitle: 'What to fix first based on risk and effort' },
  '/scan':           { title: 'Detailed Scan',        subtitle: 'Findings with step-by-step remediation playbooks' },
  '/compliance':     { title: 'Compliance',           subtitle: 'Framework tracking and control status' },
  '/drift':          { title: 'Configuration Drift',  subtitle: 'Detect unexpected changes to your environment' },
  '/ai':             { title: 'AI Assistant',         subtitle: 'Ask questions about your security posture' },
};

// ── Connection-error popup ─────────────────────────────────────────────────
function ConnectionErrorPopup({ apiBase, onClose }) {
  return (
    <>
      <div className="fixed inset-0 bg-black/30 z-[90]" onClick={onClose} />
      <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-[100] w-full max-w-sm px-4">
        <div className="rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary shadow-soft-lg overflow-hidden">
          <div className="px-5 py-4 bg-amber-50 dark:bg-amber-900/20 border-b border-amber-100 dark:border-amber-900/40 flex items-start justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-amber-100 dark:bg-amber-900/40 flex items-center justify-center flex-shrink-0">
                <FiAlertTriangle size={18} className="text-amber-600 dark:text-amber-400" />
              </div>
              <div>
                <p className="text-sm font-bold text-text-primary dark:text-text-dark-primary">Unable to connect</p>
                <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mt-0.5">Backend API unreachable</p>
              </div>
            </div>
            <button onClick={onClose} className="p-1 rounded-lg text-text-tertiary hover:bg-amber-100 dark:hover:bg-amber-900/30 transition-colors">
              <FiX size={16} />
            </button>
          </div>
          <div className="px-5 py-4 space-y-3">
            <p className="text-sm text-text-secondary dark:text-text-dark-secondary leading-relaxed">Could not reach the backend at:</p>
            <code className="block text-xs font-mono bg-bg-secondary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary px-3 py-2 rounded-lg">
              {apiBase}/health
            </code>
            <p className="text-xs text-text-tertiary dark:text-text-dark-tertiary">
              Make sure the backend is running and{' '}
              <code className="px-1 rounded bg-bg-secondary dark:bg-bg-dark-tertiary">VITE_API_URL</code> is set correctly.
            </p>
          </div>
          <div className="px-5 pb-5">
            <button onClick={onClose} className="w-full py-2.5 rounded-xl bg-brand-primary hover:bg-brand-secondary text-white text-sm font-semibold transition-colors">
              Back to Demo Mode
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ── Scan result toast ──────────────────────────────────────────────────────
function ScanToast({ result, error, onClose }) {
  useEffect(() => {
    const t = setTimeout(onClose, 6000);
    return () => clearTimeout(t);
  }, []);

  const isSuccess = !!result;

  return (
    <div className="fixed bottom-6 right-6 z-[100] w-full max-w-xs">
      <div className={`rounded-2xl border shadow-soft-lg overflow-hidden ${
        isSuccess
          ? 'bg-bg-primary dark:bg-bg-dark-secondary border-green-200 dark:border-green-900/50'
          : 'bg-bg-primary dark:bg-bg-dark-secondary border-red-200 dark:border-red-900/50'
      }`}>
        <div className={`px-4 py-3 flex items-center justify-between gap-3 ${
          isSuccess ? 'bg-green-50 dark:bg-green-900/20' : 'bg-red-50 dark:bg-red-900/20'
        }`}>
          <div className="flex items-center gap-2">
            {isSuccess
              ? <FiCheckCircle size={16} className="text-brand-primary flex-shrink-0" />
              : <FiAlertCircle size={16} className="text-severity-high flex-shrink-0" />
            }
            <p className="text-sm font-bold text-text-primary dark:text-text-dark-primary">
              {isSuccess ? 'Scan complete' : 'Scan failed'}
            </p>
          </div>
          <button onClick={onClose} className="text-text-tertiary hover:text-text-primary transition-colors">
            <FiX size={14} />
          </button>
        </div>
        <div className="px-4 py-3 space-y-1.5 text-xs text-text-secondary dark:text-text-dark-tertiary">
          {isSuccess ? (
            <>
              <div className="flex justify-between">
                <span>Scan ID</span>
                <span className="font-mono text-text-primary dark:text-text-dark-primary truncate max-w-[160px]">{result.scan_id}</span>
              </div>
              <div className="flex justify-between">
                <span>Findings detected</span>
                <span className={`font-bold ${result.total_findings > 0 ? 'text-severity-high' : 'text-brand-primary'}`}>
                  {result.total_findings}
                </span>
              </div>
              <div className="flex justify-between">
                <span>Status</span>
                <span className="text-brand-primary font-semibold capitalize">{result.status}</span>
              </div>
            </>
          ) : (
            <p className="text-severity-high">{error || 'Could not reach the backend.'}</p>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Scan input popover (live mode only) ────────────────────────────────────
function ScanInputPopover({ onConfirm, onCancel }) {
  const [subId, setSubId] = useState('');
  const inputRef = useRef(null);

  useEffect(() => { inputRef.current?.focus(); }, []);

  return (
    <>
      <div className="fixed inset-0 z-[80]" onClick={onCancel} />
      <div className="absolute top-full right-0 mt-2 z-[90] w-72 rounded-2xl border border-border-light dark:border-border-dark bg-bg-primary dark:bg-bg-dark-secondary shadow-soft-lg overflow-hidden">
        <div className="px-4 py-3 border-b border-border-light dark:border-border-dark">
          <p className="text-sm font-semibold text-text-primary dark:text-text-dark-primary">Run Azure Scan</p>
          <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mt-0.5">
            Leave blank to use the subscription configured on the backend.
          </p>
        </div>
        <div className="px-4 py-3 space-y-3">
          <div>
            <label className="text-xs font-medium text-text-secondary dark:text-text-dark-tertiary block mb-1">
              Subscription ID <span className="text-text-tertiary">(optional)</span>
            </label>
            <input
              ref={inputRef}
              type="text"
              value={subId}
              onChange={(e) => setSubId(e.target.value)}
              onKeyDown={(e) => { if (e.key === 'Enter') onConfirm(subId || undefined); if (e.key === 'Escape') onCancel(); }}
              placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
              className="w-full px-3 py-2 text-xs font-mono rounded-lg border border-border-light dark:border-border-dark bg-bg-secondary dark:bg-bg-dark-tertiary text-text-primary dark:text-text-dark-primary placeholder:text-text-tertiary dark:placeholder:text-text-dark-tertiary focus:outline-none focus:ring-1 focus:ring-brand-primary"
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => onConfirm(subId || undefined)}
              className="flex-1 py-2 text-xs font-semibold rounded-lg bg-brand-primary hover:bg-brand-secondary text-white transition-colors"
            >
              Start Scan
            </button>
            <button
              onClick={onCancel}
              className="px-3 py-2 text-xs rounded-lg border border-border-light dark:border-border-dark text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </>
  );
}

// ── Main Header ────────────────────────────────────────────────────────────
export default function Header({ onMenuToggle }) {
  const { pathname } = useLocation();
  const page = PAGE_TITLES[pathname] || { title: 'OpenShield', subtitle: '' };

  const [demoMode, setDemoMode]     = useState(api.isDemoMode());
  const [testing, setTesting]       = useState(false);
  const [showConnErr, setConnErr]   = useState(false);
  const [scanning, setScanning]     = useState(false);
  const [elapsed, setElapsed]       = useState(0);
  const [scanToast, setScanToast]   = useState(null);
  const [showScanInput, setShowScanInput] = useState(false);
  const scanBtnRef = useRef(null);

  // ── Demo/Live toggle ─────────────────────────────────────────────────────
  const handleToggle = async () => {
    if (!demoMode) {
      api.setDemoMode(true);
      setDemoMode(true);
      window.location.reload();
      return;
    }
    setTesting(true);
    const ok = await api.testConnection();
    setTesting(false);
    if (!ok) { setConnErr(true); return; }
    api.setDemoMode(false);
    setDemoMode(false);
    window.location.reload();
  };

  const closeConnErr = () => {
    setConnErr(false);
    api.setDemoMode(true);
    setDemoMode(true);
  };

  // ── Scan button click ────────────────────────────────────────────────────
  const handleScanClick = () => {
    if (demoMode) {
      // Demo mode: run immediately with no subscription input
      executeScan(undefined);
    } else {
      // Live mode: show subscription ID input first
      setShowScanInput(true);
    }
  };

  // ── Execute scan (after optional subscription ID is provided) ─────────────
  const executeScan = async (subscriptionId) => {
    setShowScanInput(false);
    setScanning(true);
    setElapsed(0);
    setScanToast(null);

    const ticker = setInterval(() => setElapsed((s) => s + 1), 1000);

    try {
      const trigger = await api.triggerScan(subscriptionId);

      if (trigger.status === 'completed' || trigger.status === 'failed') {
        setScanToast(trigger.status === 'completed' ? { result: trigger } : { error: 'Scan failed on the backend.' });
        return;
      }

      // Poll until done (max 5 min, every 4s)
      const scanId = trigger.scan_id;
      for (let i = 0; i < 75; i++) {
        await new Promise((r) => setTimeout(r, 4000));
        const scan = await api.getScan(scanId);
        if (scan?.status === 'completed') { setScanToast({ result: scan }); return; }
        if (scan?.status === 'failed')    { setScanToast({ error: `Scan ${scanId} failed.` }); return; }
      }
      setScanToast({ error: 'Scan timed out after 5 minutes. Check backend logs.' });
    } catch (err) {
      setScanToast({ error: err?.message || 'Scan failed. Is the backend running?' });
    } finally {
      clearInterval(ticker);
      setScanning(false);
      setElapsed(0);
    }
  };

  return (
    <>
      <header className="h-14 md:h-16 flex items-center justify-between px-4 md:px-6 bg-bg-primary dark:bg-bg-dark-secondary border-b border-border-light dark:border-border-dark flex-shrink-0">

        {/* Left: hamburger + title */}
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={onMenuToggle}
            className="lg:hidden w-8 h-8 rounded-lg flex items-center justify-center text-text-secondary dark:text-text-dark-tertiary hover:bg-bg-secondary dark:hover:bg-bg-dark-tertiary transition-all flex-shrink-0"
            aria-label="Open menu"
          >
            <FiMenu size={18} />
          </button>
          <div className="min-w-0">
            <h1 className="text-base md:text-lg font-bold text-text-primary dark:text-text-dark-primary leading-tight truncate">
              {page.title}
            </h1>
            {page.subtitle && (
              <p className="text-xs text-text-secondary dark:text-text-dark-tertiary mt-0.5 hidden sm:block truncate">
                {page.subtitle}
              </p>
            )}
          </div>
        </div>

        {/* Right: controls */}
        <div className="flex items-center gap-2 md:gap-2.5 flex-shrink-0">

          {/* Run Scan button + popover wrapper */}
          <div className="relative" ref={scanBtnRef}>
            <button
              onClick={handleScanClick}
              disabled={scanning}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-brand-primary hover:bg-brand-secondary disabled:opacity-60 disabled:cursor-wait text-white transition-all duration-200"
              title={demoMode ? 'Trigger a demo scan' : 'Trigger a real Azure scan'}
            >
              {scanning
                ? <FiLoader size={12} className="animate-spin" />
                : <FiZap size={12} />
              }
              <span className="hidden sm:inline">
                {scanning ? `Scanning… ${elapsed}s` : 'Run Scan'}
              </span>
            </button>

            {showScanInput && (
              <ScanInputPopover
                onConfirm={executeScan}
                onCancel={() => setShowScanInput(false)}
              />
            )}
          </div>

          {/* Demo / Live badge */}
          <button
            onClick={handleToggle}
            disabled={testing}
            title={demoMode ? 'Switch to Live API' : 'Switch to Demo Mode'}
            className={`hidden sm:inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold border transition-all duration-200 disabled:opacity-60 disabled:cursor-wait ${
              demoMode
                ? 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800 hover:bg-amber-100 dark:hover:bg-amber-900/30'
                : 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800 hover:bg-green-100 dark:hover:bg-green-900/30'
            }`}
          >
            {testing
              ? <FiLoader size={11} className="animate-spin" />
              : <span className={`w-1.5 h-1.5 rounded-full ${demoMode ? 'bg-amber-500' : 'bg-green-500'}`} />
            }
            {testing ? 'Connecting…' : demoMode ? 'DEMO' : 'LIVE'}
          </button>

          {/* Last scanned */}
          <div className="hidden sm:flex items-center gap-1.5 text-xs text-text-tertiary dark:text-text-dark-tertiary">
            <FiClock size={13} />
            <span>Last scanned: May 29, 2026 6:00 PM</span>
          </div>
        </div>
      </header>

      {showConnErr && <ConnectionErrorPopup apiBase={api.getApiBase()} onClose={closeConnErr} />}
      {scanToast && (
        <ScanToast
          result={scanToast.result}
          error={scanToast.error}
          onClose={() => setScanToast(null)}
        />
      )}
    </>
  );
}
