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
    // Always prefer the build-time token so a stale localStorage value
    // from a previous deployment never blocks authenticated requests.
    const envToken = import.meta.env.VITE_JWT_TOKEN;
    if (envToken) {
      api.setToken(envToken);
    } else if (!api.getToken()) {
      api.setToken('dev-local-token');
    }
  }, []);

  return (
    <DarkModeProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Navigate to="/monitoring" replace />} />
            <Route path="monitoring"     element={<Monitoring />}     />
            <Route path="discovery"      element={<Discovery />}      />
            <Route path="prioritization" element={<Prioritization />} />
            <Route path="scan"           element={<DetailedScan />}   />
            <Route path="compliance"     element={<Compliance />}     />
            <Route path="drift"          element={<Drift />}          />
            <Route path="ai"             element={<AILayer />}        />
          </Route>
        </Routes>
      </BrowserRouter>
    </DarkModeProvider>
  );
}
