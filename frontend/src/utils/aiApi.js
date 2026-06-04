// ─────────────────────────────────────────────────────────────────────────────
// OpenShield AI API Service
//
// Backend AI endpoints (all POST, require provider + api_key in body):
//   POST /api/ai/ask        — RAG-grounded question answering
//   POST /api/ai/summary    — RAG-grounded executive summary
//   POST /api/ai/insights   — executive summary + remediation plan
//   POST /api/ai/prioritise — AI-ranked findings by real-world exploitability
//
// If no provider key is configured all AI functions return null.
// CVE analysis calls the public GET /api/score/cve-summary endpoint.
// ─────────────────────────────────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL
  || (import.meta.env.DEV ? 'http://localhost:5000' : 'https://openshield-api.onrender.com');
const TIMEOUT = 30000;

// ── Provider settings stored in localStorage ───────────────────────────────
export const aiSettings = {
  getProvider: () => localStorage.getItem('ai_provider') || 'anthropic',
  getApiKey:   () => localStorage.getItem('ai_api_key')  || '',
  getModel:    () => localStorage.getItem('ai_model')    || '',
  save: ({ provider, apiKey, model }) => {
    if (provider)           localStorage.setItem('ai_provider', provider);
    if (apiKey !== undefined) localStorage.setItem('ai_api_key', apiKey);
    if (model !== undefined)  localStorage.setItem('ai_model', model || '');
  },
  isConfigured: () => !!localStorage.getItem('ai_api_key'),
  clear: () => {
    localStorage.removeItem('ai_api_key');
    localStorage.removeItem('ai_provider');
    localStorage.removeItem('ai_model');
  },
};

// ── Core fetch ─────────────────────────────────────────────────────────────
function getToken() { return localStorage.getItem('jwt_token'); }

async function aiApiFetch(path, body) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    const token = getToken();
    const res = await fetch(`${API_BASE}/api${path}`, {
      method:  'POST',
      signal:  ctrl.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
      body: JSON.stringify(body),
    });
    clearTimeout(t);
    if (!res.ok) throw new Error(`API ${res.status} ${res.statusText}`);
    return res.json();
  } catch (err) {
    clearTimeout(t);
    throw err;
  }
}

function buildBody(extra = {}) {
  return {
    provider: aiSettings.getProvider(),
    api_key:  aiSettings.getApiKey(),
    model:    aiSettings.getModel() || undefined,
    ...extra,
  };
}

// ── Summary normaliser ─────────────────────────────────────────────────────
function normalizeSummary(result) {
  if (!result?.summary) return null;
  return {
    overview:    result.summary,
    generatedAt: new Date().toISOString(),
    aiGenerated: true,
    provider:    result.provider,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Public AI API
// ─────────────────────────────────────────────────────────────────────────────
export const aiApi = {

  settings: aiSettings,

  // ── Chat / Q&A  POST /api/ai/ask ──────────────────────────────────────────
  chat: async ({ question, contextFinding, findings = [] }) => {
    if (!aiSettings.isConfigured()) return null;
    const result = await aiApiFetch('/ai/ask', buildBody({ question, findings }));
    return {
      answer:  result.answer  || result,
      sources: result.sources || [],
    };
  },

  // ── Executive Summary  POST /api/ai/summary ───────────────────────────────
  getSummary: async (findings = []) => {
    if (!aiSettings.isConfigured()) return null;
    try {
      return normalizeSummary(await aiApiFetch('/ai/summary', buildBody({ findings })));
    } catch {
      return null;
    }
  },

  // ── Insights  POST /api/ai/insights ───────────────────────────────────────
  getInsights: async ({ findings = [], question }) => {
    if (!aiSettings.isConfigured()) return null;
    try {
      return await aiApiFetch('/ai/insights', buildBody({ findings, question }));
    } catch {
      return null;
    }
  },

  // ── Prioritise  POST /api/ai/prioritise ───────────────────────────────────
  getPrioritisation: async (findings = []) => {
    if (!aiSettings.isConfigured()) return null;
    try {
      return await aiApiFetch('/ai/prioritise', buildBody({ findings }));
    } catch {
      return null;
    }
  },

  // ── CVE Analysis  GET /api/score/cve-summary (public) ────────────────────
  getCVEAnalysis: async () => {
    try {
      const token = getToken();
      const res = await fetch(`${API_BASE}/api/score/cve-summary`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) return null;
      return await res.json();
    } catch {
      return null;
    }
  },
};
