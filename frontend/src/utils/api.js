// ─────────────────────────────────────────────────────────────────────────────
// OpenShield API Service Layer
//
// In DEMO mode  → returns data from src/mockData/api.*.json (no network calls)
// In LIVE mode  → calls the real backend at VITE_API_URL with JWT auth
//
// Every method has a mock fallback so the app works whether or not the backend
// exists yet. When a backend endpoint is ready, it automatically takes over.
// ─────────────────────────────────────────────────────────────────────────────

// ── API-format mock data (matches exact backend response schema) ───────────
import mockHealth      from '../mockData/api.health.json';
import mockScore       from '../mockData/api.score.json';
import mockFindings    from '../mockData/api.findings.json';
import mockScans       from '../mockData/api.scans.json';
import mockScanResult  from '../mockData/api.scans.trigger.json';
import mockCIS         from '../mockData/api.compliance.cis.json';
import mockNIST        from '../mockData/api.compliance.nist.json';
import mockISO         from '../mockData/api.compliance.iso27001.json';

// ── Legacy mock data (fallback for pages whose endpoints don't exist yet) ──
import discoveryData      from '../mockData/discovery.json';
import monitoringData     from '../mockData/monitoring.json';
import scanData           from '../mockData/scan.json';
import complianceData     from '../mockData/compliance.json';
import driftData          from '../mockData/drift.json';
import prioritizationData from '../mockData/prioritization.json';
import aiData             from '../mockData/ai.json';

// ── Config ─────────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:5001';

let _demoMode = localStorage.getItem('openShieldDemoMode') !== 'false';

// ── Auth ───────────────────────────────────────────────────────────────────
const getToken = () => localStorage.getItem('jwt_token');
const setToken = (tok) => localStorage.setItem('jwt_token', tok);

// ── Core fetch ─────────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const token = getToken();
  const res = await fetch(`${API_BASE}/api${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    },
  });
  if (!res.ok) throw new Error(`API ${res.status} ${res.statusText}`);
  return res.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// Normalisers — backend returns snake_case, components expect camelCase.
// Each function handles both snake_case (live) and camelCase (mock fallback)
// gracefully via the `a || b` pattern.
// ─────────────────────────────────────────────────────────────────────────────

// Findings ──────────────────────────────────────────────────────────────────
function normalizeFinding(f) {
  const playbook = scanData.findings.find(
    (s) => s.ruleId === f.rule_id && s.resourceName === f.resource_name
  ) || {};
  return {
    id:              f.id,
    ruleId:          f.rule_id,
    ruleName:        f.rule_name,
    severity:        f.severity,
    category:        f.category,
    resourceName:    f.resource_name,
    resourceGroup:   f.resource_id?.split('/')?.[4] ?? '',
    resourceId:      f.resource_id,
    resourceType:    f.resource_type,
    description:     f.description,
    remediation:     f.remediation,
    detectedAt:      f.detected_at,
    portalSteps:     playbook.portalSteps     || [],
    cliCommands:     playbook.cliCommands     || [],
    validationSteps: playbook.validationSteps || [],
    references:      playbook.references      || [],
  };
}

// Resources (Discovery page) ────────────────────────────────────────────────
function normalizeResource(r) {
  return {
    id:            r.id,
    name:          r.name,
    type:          r.type,
    category:      r.category,
    resourceGroup: r.resource_group  || r.resourceGroup,
    subscription:  r.subscription_id || r.subscription,
    location:      r.location,
    risk:          r.risk,
    discoveredAt:  r.discovered_at   || r.discoveredAt,
    config:        r.config          || {},
  };
}

function normalizeResourcesResponse(data) {
  const s = data.summary || {};
  return {
    summary: {
      total:       s.total,
      byCategory:  s.by_category   || s.byCategory  || {},
      byRiskLevel: s.by_risk_level  || s.byRiskLevel || {},
      lastScanAt:  s.last_scan_at   || s.lastScanAt,
    },
    resources: (data.resources || []).map(normalizeResource),
  };
}

// Prioritization ────────────────────────────────────────────────────────────
function normalizePrioritizationResponse(data) {
  return {
    matrix: (data.matrix || []).map((m) => ({
      id:                m.id,
      ruleId:            m.rule_id            || m.ruleId,
      name:              m.name,
      risk:              m.risk,
      effort:            m.effort,
      category:          m.category,
      severity:          m.severity,
      affectedResources: m.affected_resources || m.affectedResources,
      resource:          m.resource,
    })),
    rankings: (data.rankings || []).map((r) => ({
      rank:     r.rank,
      ruleId:   r.rule_id   || r.ruleId,
      name:     r.name,
      score:    r.score,
      severity: r.severity,
      category: r.category,
      effort:   r.effort,
      impact:   r.impact,
      resource: r.resource,
    })),
    actionItems: (data.action_items || data.actionItems || []).map((a) => ({
      id:       a.id,
      action:   a.action,
      impact:   a.impact,
      effort:   a.effort,
      eta:      a.eta,
      ruleId:   a.rule_id   || a.ruleId,
      resource: a.resource,
    })),
    summary: data.summary,
  };
}

// Drift ─────────────────────────────────────────────────────────────────────
function normalizeDriftEvent(e) {
  return {
    id:            e.id,
    type:          e.type,
    severity:      e.severity,
    resourceName:  e.resource_name  || e.resourceName,
    resourceType:  e.resource_type  || e.resourceType,
    resourceGroup: e.resource_group || e.resourceGroup,
    field:         e.field,
    oldValue:      e.old_value      ?? e.oldValue,
    newValue:      e.new_value      ?? e.newValue,
    changedBy:     e.changed_by     || e.changedBy,
    changedAt:     e.changed_at     || e.changedAt,
    ruleViolated:  e.rule_violated  ?? e.ruleViolated,
  };
}

function normalizeDriftResponse(data) {
  const s = data.summary || {};
  return {
    summary: {
      total:       s.total,
      added:       s.added,
      removed:     s.removed,
      modified:    s.modified,
      lastChecked: s.last_checked || s.lastChecked,
    },
    events: (data.events || []).map(normalizeDriftEvent),
  };
}

// Playbook ──────────────────────────────────────────────────────────────────
function normalizePlaybook(p) {
  return {
    portalSteps:     p.portal_steps     || p.portalSteps     || [],
    cliCommands:     p.cli_commands     || p.cliCommands     || [],
    validationSteps: p.validation_steps || p.validationSteps || [],
    references:      p.references       || [],
  };
}

// Compliance (combines 3 framework endpoints → old page format) ─────────────
function buildComplianceFromFrameworks(cis, nist, iso) {
  const mapFramework = (f, id, color) => ({
    id,
    name:           f.framework,
    version:        f.version,
    score:          f.score_percent,
    totalControls:  f.total_controls,
    passing:        f.passed,
    failing:        f.failed,
    notApplicable:  f.total_controls - f.passed - f.failed,
    lastAssessed:   new Date().toISOString(),
    color,
  });

  const mapControl = (c, frameworkName) => ({
    id:        c.control_id,
    framework: frameworkName,
    name:      c.control_name,
    status:    c.status,
    ruleId:    c.rule_id,
    // severity and category not returned by backend yet — leave blank
    severity:  c.severity  || 'MEDIUM',
    category:  c.category  || 'General',
    resources: c.resources || 0,
  });

  return {
    frameworks: [
      mapFramework(cis,  'cis',      '#3b82f6'),
      mapFramework(nist, 'nist',     '#8b5cf6'),
      mapFramework(iso,  'iso27001', '#10b981'),
    ],
    controls: [
      ...(cis.controls  || []).map((c) => mapControl(c, cis.framework)),
      ...(nist.controls || []).map((c) => mapControl(c, nist.framework)),
      ...(iso.controls  || []).map((c) => mapControl(c, iso.framework)),
    ],
    // Trend has no backend endpoint yet — keep from mock
    trend: complianceData.trend,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────
export const api = {

  // ── Mode control ──────────────────────────────────────────────────────────
  setDemoMode: (on) => { _demoMode = on; localStorage.setItem('openShieldDemoMode', String(on)); },
  isDemoMode:  () => _demoMode,
  getApiBase:  () => API_BASE,

  // ── Connection test ────────────────────────────────────────────────────────
  testConnection: async () => {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 5000);
    try {
      const res = await fetch(`${API_BASE}/health`, { signal: ctrl.signal });
      clearTimeout(t); return res.ok;
    } catch { clearTimeout(t); return false; }
  },

  // ── Health ─────────────────────────────────────────────────────────────────
  // GET /health
  health: async () => {
    try { const r = await fetch(`${API_BASE}/health`); return r.ok ? r.json() : mockHealth; }
    catch { return mockHealth; }
  },

  // ── Score ──────────────────────────────────────────────────────────────────
  // GET /api/score
  getScore: async () => {
    if (_demoMode) return mockScore;
    return apiFetch('/score');
  },

  // ── Findings list ──────────────────────────────────────────────────────────
  // GET /api/findings
  getFindings: async (filters = {}) => {
    if (_demoMode) return mockFindings.findings.map(normalizeFinding);
    const params = new URLSearchParams(Object.entries(filters).filter(([, v]) => v != null && v !== ''));
    const data = await apiFetch(`/findings${params.toString() ? '?' + params : ''}`);
    return data.findings.map(normalizeFinding);
  },

  // ── Single finding ─────────────────────────────────────────────────────────
  // GET /api/findings/:id
  getFinding: async (id) => {
    if (_demoMode) {
      const f = mockFindings.findings.find((x) => x.id === id);
      return f ? normalizeFinding(f) : null;
    }
    return normalizeFinding(await apiFetch(`/findings/${id}`));
  },

  // ── Playbook ───────────────────────────────────────────────────────────────
  // GET /api/findings/:id/playbook
  getPlaybook: async (id) => {
    if (_demoMode) {
      const f = scanData.findings.find((s) => s.id === id);
      return f ? normalizePlaybook(f) : { portalSteps: [], cliCommands: [], validationSteps: [], references: [] };
    }
    try {
      return normalizePlaybook(await apiFetch(`/findings/${id}/playbook`));
    } catch {
      // Endpoint not yet implemented — fall back to scan.json enrichment
      const f = scanData.findings.find((s) => s.id === id);
      return f ? normalizePlaybook(f) : { portalSteps: [], cliCommands: [], validationSteps: [], references: [] };
    }
  },

  // ── Resources (Discovery page) ─────────────────────────────────────────────
  // GET /api/resources
  getResources: async () => {
    if (_demoMode) return discoveryData;
    try {
      return normalizeResourcesResponse(await apiFetch('/resources'));
    } catch {
      return discoveryData;
    }
  },
  getResourceSummary: async () => {
    const d = await api.getResources();
    return d.summary;
  },

  // ── Prioritization ─────────────────────────────────────────────────────────
  // GET /api/prioritization
  getPrioritization: async () => {
    if (_demoMode) return prioritizationData;
    try {
      return normalizePrioritizationResponse(await apiFetch('/prioritization'));
    } catch {
      return prioritizationData;
    }
  },
  getPriorityMatrix: async () => { const d = await api.getPrioritization(); return d.matrix; },
  getRiskRankings:   async () => { const d = await api.getPrioritization(); return d.rankings; },

  // ── Drift ──────────────────────────────────────────────────────────────────
  // GET /api/drift
  getDrift: async () => {
    if (_demoMode) return driftData;
    try {
      return normalizeDriftResponse(await apiFetch('/drift'));
    } catch {
      return driftData;
    }
  },
  getDriftEvents: async () => { const d = await api.getDrift(); return d.events; },

  // ── Scans ──────────────────────────────────────────────────────────────────
  // GET /api/scans
  getScans: async () => {
    if (_demoMode) return mockScans;
    return apiFetch('/scans');
  },
  // POST /api/scans/trigger
  triggerScan: async (subscriptionId) => {
    if (_demoMode) return mockScanResult;
    return apiFetch('/scans/trigger', {
      method: 'POST',
      body: JSON.stringify(subscriptionId ? { subscription_id: subscriptionId } : {}),
    });
  },
  // GET /api/scans/:id
  getScan: async (scanId) => {
    if (_demoMode) return mockScans.scans.find((s) => s.scan_id === scanId) ?? mockScanResult;
    try {
      return await apiFetch(`/scans/${scanId}`);
    } catch {
      const data = await apiFetch('/scans');
      return data.scans.find((s) => s.scan_id === scanId) ?? null;
    }
  },

  // ── Compliance ─────────────────────────────────────────────────────────────
  // GET /api/compliance/cis | /nist | /iso27001
  getComplianceCIS:      async () => _demoMode ? mockCIS  : apiFetch('/compliance/cis'),
  getComplianceNIST:     async () => _demoMode ? mockNIST : apiFetch('/compliance/nist'),
  getComplianceISO27001: async () => _demoMode ? mockISO  : apiFetch('/compliance/iso27001'),

  // Combined — returns old page format (for Compliance page)
  getCompliance: async () => {
    if (_demoMode) return complianceData;
    try {
      const [cis, nist, iso] = await Promise.all([
        apiFetch('/compliance/cis'),
        apiFetch('/compliance/nist'),
        apiFetch('/compliance/iso27001'),
      ]);
      return buildComplianceFromFrameworks(cis, nist, iso);
    } catch {
      return complianceData;
    }
  },
  getFrameworks: async () => { const d = await api.getCompliance(); return d.frameworks; },

  // ── Monitoring (no backend endpoint yet — uses mock) ──────────────────────
  getMonitoring: async () => monitoringData,
  getTrend:      async () => monitoringData.trend,

  // ── AI chat data ───────────────────────────────────────────────────────────
  getAIMessages:    async () => aiData.messages,
  getAISuggestions: async () => aiData.suggestions,

  // ── JWT helpers ────────────────────────────────────────────────────────────
  setToken,
  getToken,
};

export default api;
