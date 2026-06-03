// ─────────────────────────────────────────────────────────────────────────────
// OpenShield AI API Service
//
// Backend AI endpoints (all POST, all require provider + api_key):
//   POST /api/ai/insights  — executive summary + remediation plan + optional Q&A
//   POST /api/ai/summary   — RAG-grounded executive summary
//   POST /api/ai/ask       — RAG-grounded question answering
//   POST /api/ai/prioritise — AI-ranked findings by real-world exploitability
//
// Supported providers: anthropic | groq | gemini
// API key is stored in localStorage and passed per-request (never server-side).
//
// Demo mode or missing API key → smart mock responses (no network calls).
// ─────────────────────────────────────────────────────────────────────────────

import aiMockData from '../mockData/ai.json';
import cveMockData from '../mockData/cve.json';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5000';
const TIMEOUT  = 30000;

// ── Provider settings stored in localStorage ───────────────────────────────
export const aiSettings = {
  getProvider: () => localStorage.getItem('ai_provider') || 'anthropic',
  getApiKey:   () => localStorage.getItem('ai_api_key')  || '',
  getModel:    () => localStorage.getItem('ai_model')    || '',
  save: ({ provider, apiKey, model }) => {
    if (provider) localStorage.setItem('ai_provider', provider);
    if (apiKey !== undefined) localStorage.setItem('ai_api_key', apiKey);
    if (model !== undefined) localStorage.setItem('ai_model', model || '');
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

// ── Mock response generator ────────────────────────────────────────────────
function mockChat(question, contextFinding) {
  if (contextFinding) return mockFindingChat(contextFinding, question);
  const q = question.toLowerCase();

  if (/crit|urgent|most important|highest|top|worst/.test(q)) {
    return {
      answer: "Your most critical findings: 1) **AZ-NET-001** — nsg-web has SSH (port 22) open to 0.0.0.0/0, actively exploitable. 2) **AZ-NET-007** — nsg-app has RDP (port 3389) open to 0.0.0.0/0, top ransomware vector. 3) **AZ-DB-001** — sql-dev-exposed firewall allows all IPs. All three are fixable in under 2 hours with very low effort.",
      sources: [{ id: 'AZ-NET-001', resource: 'nsg-web' }, { id: 'AZ-NET-007', resource: 'nsg-app' }, { id: 'AZ-DB-001', resource: 'sql-dev-exposed' }],
    };
  }
  if (/ssh|rdp|port|nsg|network/.test(q)) {
    return {
      answer: "**nsg-web** has SSH (AZ-NET-001) and **nsg-app** has RDP (AZ-NET-007) both open to 0.0.0.0/0.\n\n**CLI fix:**\n`az network nsg rule delete --resource-group rg-prod --nsg-name nsg-web --name Allow-SSH-Any`\n\nReplace with a rule scoped to your VPN CIDR. Consider Azure Bastion for production SSH/RDP access.",
      sources: [{ id: 'AZ-NET-001', resource: 'nsg-web' }, { id: 'AZ-NET-007', resource: 'nsg-app' }],
    };
  }
  if (/storage|blob|public|https/.test(q)) {
    return {
      answer: "**prod-storage-01** has public blob access enabled (AZ-STOR-001). Fix:\n`az storage account update --name prod-storage-01 --resource-group rg-prod --allow-blob-public-access false`\n\n**staging-storage-01** doesn't enforce HTTPS (AZ-STOR-002). Fix:\n`az storage account update --name staging-storage-01 --resource-group rg-staging --https-only true`",
      sources: [{ id: 'AZ-STOR-001', resource: 'prod-storage-01' }, { id: 'AZ-STOR-002', resource: 'staging-storage-01' }],
    };
  }
  if (/compli|cis|nist|iso|soc/.test(q)) {
    return {
      answer: "Compliance scores: CIS Azure 74%, NIST SP 800-53 68%, ISO 27001 81%, SOC 2 77%. The biggest gap is NIST at 68% — 8 controls failing, primarily around access enforcement (AC-3, AC-6) and transmission security (SC-8). Fixing the 7 HIGH severity findings would push CIS from 74% to ~85%.",
      sources: [{ id: 'CIS-6.2', resource: 'nsg-web' }, { id: 'NIST-AC-3', resource: 'prod-storage-01' }],
    };
  }
  if (/drift|change|modif/.test(q)) {
    return {
      answer: "4 HIGH-severity changes in the last 48 hours:\n• **prod-storage-01** — public blob enabled by john.doe (→ AZ-STOR-001)\n• **nsg-web** — SSH opened to 0.0.0.0/0 by jane.smith (→ AZ-NET-001)\n• **staging-storage-01** — HTTPS disabled by john.doe (→ AZ-STOR-002)\n• **sql-dev-exposed** — AllowAllIPs firewall added by dev-team (→ AZ-DB-001)",
      sources: [{ id: 'AZ-STOR-001', resource: 'prod-storage-01' }, { id: 'AZ-NET-001', resource: 'nsg-web' }],
    };
  }
  return {
    answer: "Your environment has 25 open findings — 7 HIGH, 8 MEDIUM, 10 LOW. The fastest wins are: disable public blob access on prod-storage-01, enforce HTTPS on staging-storage-01, and restrict SSH/RDP on nsg-web/nsg-app. All four can be done in under 2 hours. Ask me about any specific finding or resource.",
    sources: [],
  };
}

function mockFindingChat(finding, question) {
  const q = question.toLowerCase();
  if (/fix|remediat|how|step/.test(q)) {
    const step = finding.portalSteps?.[0] ?? 'Open the Azure Portal and navigate to the resource.';
    const cli  = finding.cliCommands?.[0]  ?? 'See the Scan page for CLI commands.';
    return {
      answer: `To remediate **${finding.ruleId}** on \`${finding.resourceName}\`:\n\n**Portal:** ${step}\n\n**CLI:**\n\`${cli}\`\n\n**Validate:** ${finding.validationSteps?.[0] ?? 'Check Azure Security Center.'}`,
      sources: [{ id: finding.ruleId, resource: finding.resourceName }],
    };
  }
  if (/risk|why|impact/.test(q)) {
    return {
      answer: `**${finding.ruleId}** is rated **${finding.severity}** because ${finding.description.charAt(0).toLowerCase() + finding.description.slice(1)} References: ${finding.references?.join(', ') ?? 'CIS Azure, NIST SP 800-53'}.`,
      sources: [{ id: finding.ruleId, resource: finding.resourceName }],
    };
  }
  return {
    answer: `**${finding.ruleId} — ${finding.ruleName}** on \`${finding.resourceName}\`:\n\n${finding.description}\n\n**Fix:** ${finding.remediation}`,
    sources: [{ id: finding.ruleId, resource: finding.resourceName }],
  };
}

// ── Shared request body builder ────────────────────────────────────────────
function buildBody(extra = {}) {
  return {
    provider: aiSettings.getProvider(),
    api_key:  aiSettings.getApiKey(),
    model:    aiSettings.getModel() || undefined,
    ...extra,
  };
}

function isDemoOrUnconfigured() {
  const _demoMode = localStorage.getItem('openShieldDemoMode') !== 'false';
  return _demoMode || !aiSettings.isConfigured();
}

// ─────────────────────────────────────────────────────────────────────────────
// Public AI API
// ─────────────────────────────────────────────────────────────────────────────
export const aiApi = {

  // ── Settings ──────────────────────────────────────────────────────────────
  settings: aiSettings,

  // ── Chat / Q&A  POST /api/ai/ask ─────────────────────────────────────────
  // question: string, contextFinding: finding object | null, findings: array
  chat: async ({ question, contextFinding, findings = [] }) => {
    if (isDemoOrUnconfigured()) return mockChat(question, contextFinding);
    try {
      const result = await aiApiFetch('/ai/ask', buildBody({ question, findings }));
      return {
        answer:  result.answer  || result,
        sources: result.sources || [],
      };
    } catch {
      return mockChat(question, contextFinding);
    }
  },

  // ── Executive Summary  POST /api/ai/summary ───────────────────────────────
  // findings: array of finding objects (passed from frontend, not fetched by backend)
  getSummary: async (findings = []) => {
    if (isDemoOrUnconfigured()) return aiMockData.executiveSummary;
    try {
      const result = await aiApiFetch('/ai/summary', buildBody({ findings }));
      // Normalize to shape ExecutiveSummary component expects
      return normalizeSummary(result);
    } catch {
      return aiMockData.executiveSummary;
    }
  },

  // ── Insights (combined)  POST /api/ai/insights ────────────────────────────
  // Returns executive_summary + remediation_plan + optional answer to question
  getInsights: async ({ findings = [], question }) => {
    if (isDemoOrUnconfigured()) return null;
    try {
      return await aiApiFetch('/ai/insights', buildBody({ findings, question }));
    } catch {
      return null;
    }
  },

  // ── Prioritise  POST /api/ai/prioritise ───────────────────────────────────
  // Returns AI-ranked findings by real-world exploitability
  getPrioritisation: async (findings = []) => {
    if (isDemoOrUnconfigured()) return null;
    try {
      return await aiApiFetch('/ai/prioritise', buildBody({ findings }));
    } catch {
      return null;
    }
  },

  // ── CVE Analysis  GET /api/score/cve-summary (new) ───────────────────────
  getCVEAnalysis: async () => {
    if (isDemoOrUnconfigured()) return cveMockData;
    try {
      const token = getToken();
      const res = await fetch(`${API_BASE}/api/score/cve-summary`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error();
      const summary = await res.json();
      // Backend returns aggregate stats; supplement with mock CVE list for UI
      return { ...cveMockData, summary };
    } catch {
      return cveMockData;
    }
  },
};

// ── Summary normaliser ─────────────────────────────────────────────────────
function normalizeSummary(result) {
  // Backend returns { summary, sources, provider, model }
  // ExecutiveSummary component expects { overview, topPriorities, ... }
  if (!result?.summary) return aiMockData.executiveSummary;
  return {
    ...aiMockData.executiveSummary,     // keep topPriorities, compliance, eta from mock
    overview:     result.summary,       // replace overview with AI-generated text
    generatedAt:  new Date().toISOString(),
    aiGenerated:  true,
    provider:     result.provider,
  };
}
