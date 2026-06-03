// ─────────────────────────────────────────────────────────────────────────────
// OpenShield API Service Layer
//
// Demo mode → mock JSON files (no network calls, no API key needed)
// Live mode → real Flask backend at VITE_API_URL with JWT auth
//
// Every live call has a graceful mock fallback so the app always works.
// ─────────────────────────────────────────────────────────────────────────────

// ── API-format mock data ───────────────────────────────────────────────────
import mockHealth     from '../mockData/api.health.json';
import mockScore      from '../mockData/api.score.json';
import mockFindings   from '../mockData/api.findings.json';
import mockScans      from '../mockData/api.scans.json';
import mockScanResult from '../mockData/api.scans.trigger.json';
import mockCIS        from '../mockData/api.compliance.cis.json';
import mockNIST       from '../mockData/api.compliance.nist.json';
import mockISO        from '../mockData/api.compliance.iso27001.json';

// ── Legacy mock data (fallback for endpoints not yet in backend) ───────────
import discoveryData      from '../mockData/discovery.json';
import monitoringData     from '../mockData/monitoring.json';
import scanData           from '../mockData/scan.json';
import complianceData     from '../mockData/compliance.json';
import driftData          from '../mockData/drift.json';
import prioritizationData from '../mockData/prioritization.json';
import aiData             from '../mockData/ai.json';

// ── Config ─────────────────────────────────────────────────────────────────
// Production (Vercel): set VITE_API_URL=https://openshield-api.onrender.com
// Local dev: falls back to http://localhost:5000
// If neither is available in production, API calls fail loudly (no silent localhost fallback)
const API_BASE = import.meta.env.VITE_API_URL || (import.meta.env.DEV ? 'http://localhost:5000' : '');

let _demoMode = localStorage.getItem('openShieldDemoMode') !== 'false';

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
// Normalisers — map backend snake_case + varying shapes → components expect
// ─────────────────────────────────────────────────────────────────────────────

// Score: backend returns plain int (68), mock returns { score, max_score }
function normalizeScore(raw) {
  if (typeof raw === 'number') return { score: raw, max_score: 100 };
  return { score: raw.score ?? raw.score_percent ?? 0, max_score: raw.max_score ?? 100 };
}

// Findings ──────────────────────────────────────────────────────────────────
function normalizeFinding(f) {
  // Enrich with playbook steps from scan.json (works for both camelCase mock + snake_case live)
  const ruleId = f.rule_id || f.ruleId;
  const resourceName = f.resource_name || f.resourceName;
  const playbook = scanData.findings.find(
    (s) => s.ruleId === ruleId && s.resourceName === resourceName
  ) || {};

  return {
    id:               f.id,
    ruleId:           ruleId,
    ruleName:         f.rule_name     || f.ruleName,
    severity:         f.severity,
    category:         f.category,
    resourceName:     resourceName,
    resourceGroup:    (f.resource_id || f.resourceId)?.split('/')?.[4] ?? f.resourceGroup ?? '',
    resourceId:       f.resource_id   || f.resourceId,
    resourceType:     f.resource_type || f.resourceType,
    description:      f.description,
    remediation:      f.remediation,
    detectedAt:       f.detected_at   || f.detectedAt,
    // CVE fields (new from backend)
    cveReferences:    f.cve_references    || f.cveReferences    || [],
    cvssScore:        f.cvss_score        ?? f.cvssScore         ?? null,
    exploitAvailable: f.exploit_available ?? f.exploitAvailable  ?? false,
    frameworks:       f.frameworks        || {},
    // Playbook — enriched from internal library
    portalSteps:      playbook.portalSteps     || [],
    cliCommands:      playbook.cliCommands     || [],
    validationSteps:  playbook.validationSteps || [],
    references:       playbook.references      || [],
  };
}

// Resources (Discovery) ─────────────────────────────────────────────────────
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

// Scans: backend returns plain array [], mock returns { count, scans: [] }
function normalizeScans(data) {
  const scans = Array.isArray(data) ? data : (data.scans || []);
  return { count: scans.length, scans };
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

// Compliance: backend returns { framework, version, total_controls, passed,
//   failed, score_percent, controls: [{ rule_id, control_id, control_name, status }] }
// Map to shape the compliance page expects
function normalizeComplianceFramework(data, id, color) {
  return {
    id,
    name:           data.framework,
    version:        data.version,
    score:          data.score_percent,
    totalControls:  data.total_controls,
    passing:        data.passed,
    failing:        data.failed,
    notApplicable:  (data.total_controls || 0) - (data.passed || 0) - (data.failed || 0),
    lastAssessed:   new Date().toISOString(),
    color,
  };
}

function normalizeComplianceControl(c, frameworkName) {
  return {
    id:        c.control_id,
    framework: frameworkName,
    name:      c.control_name,
    status:    c.status,
    ruleId:    c.rule_id,
    severity:  c.severity  || 'MEDIUM',
    category:  c.category  || 'General',
    resources: c.resources || 0,
  };
}

function buildComplianceFromFrameworks(cis, nist, iso) {
  return {
    frameworks: [
      normalizeComplianceFramework(cis,  'cis',      '#3b82f6'),
      normalizeComplianceFramework(nist, 'nist',     '#8b5cf6'),
      normalizeComplianceFramework(iso,  'iso27001', '#10b981'),
    ],
    controls: [
      ...(cis.controls  || []).map((c) => normalizeComplianceControl(c, cis.framework)),
      ...(nist.controls || []).map((c) => normalizeComplianceControl(c, nist.framework)),
      ...(iso.controls  || []).map((c) => normalizeComplianceControl(c, iso.framework)),
    ],
    trend: complianceData.trend,  // no trend endpoint on backend yet
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

  // ── Health  GET /health ────────────────────────────────────────────────────
  health: async () => {
    try { const r = await fetch(`${API_BASE}/health`); return r.ok ? r.json() : mockHealth; }
    catch { return mockHealth; }
  },

  // ── Score  GET /api/score ──────────────────────────────────────────────────
  // Backend returns a plain integer; normalizeScore wraps it
  getScore: async () => {
    if (_demoMode) return mockScore;
    try { return normalizeScore(await apiFetch('/score')); }
    catch { return mockScore; }
  },

  // ── CVE Summary  GET /api/score/cve-summary  (new endpoint) ───────────────
  getCVESummary: async () => {
    if (_demoMode) return null;
    try { return await apiFetch('/score/cve-summary'); }
    catch { return null; }
  },

  // ── Findings  GET /api/findings ────────────────────────────────────────────
  getFindings: async (filters = {}) => {
    if (_demoMode) return mockFindings.findings.map(normalizeFinding);
    const params = new URLSearchParams(Object.entries(filters).filter(([, v]) => v != null && v !== ''));
    const data = await apiFetch(`/findings${params.toString() ? '?' + params : ''}`);
    return (data.findings || data).map(normalizeFinding);
  },

  // ── Single finding  GET /api/findings/:id ─────────────────────────────────
  getFinding: async (id) => {
    if (_demoMode) {
      const f = mockFindings.findings.find((x) => x.id === id);
      return f ? normalizeFinding(f) : null;
    }
    return normalizeFinding(await apiFetch(`/findings/${id}`));
  },

  // ── Playbook  GET /api/findings/:id/playbook ───────────────────────────────
  getPlaybook: async (id) => {
    if (_demoMode) {
      const f = scanData.findings.find((s) => s.id === id);
      return f ? normalizePlaybook(f) : { portalSteps: [], cliCommands: [], validationSteps: [], references: [] };
    }
    try {
      return normalizePlaybook(await apiFetch(`/findings/${id}/playbook`));
    } catch {
      const f = scanData.findings.find((s) => s.id === id);
      return f ? normalizePlaybook(f) : { portalSteps: [], cliCommands: [], validationSteps: [], references: [] };
    }
  },

  // ── Resources (Discovery)  GET /api/resources ──────────────────────────────
  getResources: async () => {
    if (_demoMode) return discoveryData;
    try { return normalizeResourcesResponse(await apiFetch('/resources')); }
    catch { return discoveryData; }
  },
  getResourceSummary: async () => { const d = await api.getResources(); return d.summary; },

  // ── Prioritization  GET /api/prioritization ────────────────────────────────
  getPrioritization: async () => {
    if (_demoMode) return prioritizationData;
    try { return normalizePrioritizationResponse(await apiFetch('/prioritization')); }
    catch { return prioritizationData; }
  },
  getPriorityMatrix: async () => { const d = await api.getPrioritization(); return d.matrix; },
  getRiskRankings:   async () => { const d = await api.getPrioritization(); return d.rankings; },

  // ── Drift  GET /api/drift ──────────────────────────────────────────────────
  getDrift: async () => {
    if (_demoMode) return driftData;
    try { return normalizeDriftResponse(await apiFetch('/drift')); }
    catch { return driftData; }
  },
  getDriftEvents: async () => { const d = await api.getDrift(); return d.events; },

  // ── Scans  GET /api/scans ─────────────────────────────────────────────────
  // Backend returns a plain array; normalizeScans wraps it
  getScans: async () => {
    if (_demoMode) return mockScans;
    try { return normalizeScans(await apiFetch('/scans')); }
    catch { return mockScans; }
  },

  // ── Trigger scan  POST /api/scans/trigger ─────────────────────────────────
  triggerScan: async (subscriptionId) => {
    if (_demoMode) return mockScanResult;
    return apiFetch('/scans/trigger', {
      method: 'POST',
      body: JSON.stringify(subscriptionId ? { subscription_id: subscriptionId } : {}),
    });
  },

  // ── Single scan  GET /api/scans/:id ──────────────────────────────────────
  getScan: async (scanId) => {
    if (_demoMode) return mockScans.scans.find((s) => s.scan_id === scanId) ?? mockScanResult;
    try { return await apiFetch(`/scans/${scanId}`); }
    catch {
      const data = await apiFetch('/scans');
      const scans = normalizeScans(data).scans;
      return scans.find((s) => s.scan_id === scanId) ?? null;
    }
  },

  // ── Compliance  GET /api/compliance/<framework> ────────────────────────────
  // Backend supports: cis, nist, iso27001, soc2
  getComplianceCIS:      async () => _demoMode ? mockCIS  : apiFetch('/compliance/cis'),
  getComplianceNIST:     async () => _demoMode ? mockNIST : apiFetch('/compliance/nist'),
  getComplianceISO27001: async () => _demoMode ? mockISO  : apiFetch('/compliance/iso27001'),

  // Combined — returns page format (frameworks[], controls[], trend)
  getCompliance: async () => {
    if (_demoMode) return complianceData;
    try {
      const [cis, nist, iso] = await Promise.all([
        apiFetch('/compliance/cis'),
        apiFetch('/compliance/nist'),
        apiFetch('/compliance/iso27001'),
      ]);
      return buildComplianceFromFrameworks(cis, nist, iso);
    } catch { return complianceData; }
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
