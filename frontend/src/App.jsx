import React, { useEffect } from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { DarkModeProvider } from './contexts/DarkModeContext';
import { api } from './utils/api';
import Layout from './components/layout/Layout';
import Discovery from './pages/Discovery';
import Prioritization from './pages/Prioritization';
import Monitoring from './pages/Monitoring';
import DetailedScan from './pages/DetailedScan';
import Compliance from './pages/Compliance';
import Drift from './pages/Drift';
import AILayer from './pages/AILayer';

// Probe /health with up to `maxAttempts` retries spaced `delayMs` apart.
// The Render free tier can take 30–60 s to wake from idle; we give it ~75 s total.
async function probeBackend(maxAttempts = 5, delayMs = 15000) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      const data = await api.health();
      if (data?.status === 'ok') return true;
    } catch {
      // continue
    }
    if (i < maxAttempts - 1) await new Promise((r) => setTimeout(r, delayMs));
  }
  return false;
}

export default function App() {
  useEffect(() => {
    // Bootstrap JWT token.
    // In production (Vercel): set VITE_JWT_TOKEN to a pre-generated HS256 JWT
    // signed with the same JWT_SECRET as the Render backend.
    // In local dev: falls back to 'dev-demo-token' (only works when backend
    // uses the default insecure JWT_SECRET = 'change-me-in-production').
    if (!api.getToken()) {
      api.setToken(import.meta.env.VITE_JWT_TOKEN || 'dev-demo-token');
    }

    // Probe the backend, tolerating Render's cold-start delay (~30–60 s).
    // If the backend comes online: live data is already the default, nothing to do.
    // If every probe fails: fall back to demo mode in-memory only (persist=false)
    //   so the next page refresh retries live automatically once the backend wakes.
    probeBackend().then((online) => {
      if (!online && !api.isDemoMode()) {
        console.warn('[OpenShield] Backend unreachable after retries — showing demo data. Will retry on next load.');
        api.setDemoMode(true, false); // non-persisted: retried automatically on reload
      } else if (online) {
        console.info('[OpenShield] Backend API online — serving live data.');
      }
    });
  }, []);

  return (
    <DarkModeProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/monitoring" replace />} />
            <Route path="monitoring"     element={<Monitoring />}    />
            <Route path="discovery"      element={<Discovery />}     />
            <Route path="prioritization" element={<Prioritization />} />
            <Route path="scan"           element={<DetailedScan />}  />
            <Route path="compliance"     element={<Compliance />}    />
            <Route path="drift"          element={<Drift />}         />
            <Route path="ai"             element={<AILayer />}       />
          </Route>
        </Routes>
      </BrowserRouter>
    </DarkModeProvider>
  );
}
