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

    // Probe backend health; auto-enable demo mode if unreachable
    api.health()
      .then((data) => {
        if (data?.status === 'ok' && api.isDemoMode()) {
          // Backend is online — inform the console, but don't override user's choice
          console.info('[OpenShield] Backend API is online. Toggle off Demo Mode to use live data.');
        }
      })
      .catch(() => {
        if (!api.isDemoMode()) {
          console.warn('[OpenShield] Backend unreachable — switching to Demo Mode.');
          api.setDemoMode(true);
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
