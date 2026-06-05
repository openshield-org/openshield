// ─────────────────────────────────────────────────────────────────────────────
// OpenShield API Service Layer
//
// All data comes from the Flask backend. No mock fallbacks.
// The backend always has data — either seeded or from a real scan.
// ─────────────────────────────────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL
  || (import.meta.env.DEV ? 'http://localhost:5000' : 'https://openshield-api.onrender.com');

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
// Normalisers — map backend snake_case → component props
// ─────────────────────────────────────────────────────────────────────────────

function normalizeScore(raw) {
  if (typeof raw === 'number') return { score: raw, max_score: 100 };
  return { score: raw.score ?? raw.score_percent ?? 0, max_score: raw.max_score ?? 100 };
}

function normalizeFinding(f) {
  return {
    id:               f.id,
    ruleId:           f.rule_id          || f.ruleId,
    ruleName:         f.rule_name        || f.ruleName,
    severity:         f.severity,
    category:         f.category,
    resourceName:     f.resource_name    || f.resourceName,
    resourceGroup:    (f.resource_id || f.resourceId)?.split('/')?.[4] ?? f.resourceGroup ?? '',
    resourceId:       f.resource_id      || f.resourceId,
    resourceType:     f.resource_type    || f.resourceType,
    description:      f.description,
    remediation:      f.remediation,
    detectedAt:       f.detected_at      || f.detectedAt,
    cveReferences:    f.cve_references   || f.cveReferences   || [],
    cvssScore:        f.cvss_score       ?? f.cvssScore        ?? null,
    exploitAvailable: f.exploit_available ?? f.exploitAvailable ?? false,
    frameworks:       f.frameworks       || {},
    // Playbook steps fetched separately via getPlaybook(id)
    portalSteps:      [],
    cliCommands:      [],
    validationSteps:  [],
    references:       [],
  };
}

function normalizeResource(r) {
  return {
    id:            r.id,
    name:          r.name,
    type:          r.type,
    category:      r.category,
    resourceGroup: r.resource_group  || r.resourceGroup,
    subscription:  r.subscription_id || r.subscription,
    location:      r.location,
    risk:          r.risk_level      || r.risk,
    findingCount:  r.finding_count   || r.findingCount || 0,
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

function normalizeScans(data) {
  const scans = Array.isArray(data) ? data : (data.scans || []);
  return { count: scans.length, scans };
}

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
      ruleId:   a.rule_id || a.ruleId,
      resource: a.resource,
    })),
    summary: data.summary,
  };
}

function normalizeDriftEvent(e) {
  return {
    id:            e.id,
    type:          e.type,
    severity:      e.severity,
    ruleId:        e.rule_id       || e.ruleId,
    ruleName:      e.rule_name     || e.ruleName,
    resourceName:  e.resource_name || e.resourceName,
    resourceType:  e.resource_type || e.resourceType,
    resourceGroup: e.resource_group || e.resourceGroup,
    field:         e.field,
    oldValue:      e.old_value     ?? e.oldValue,
    newValue:      e.new_value     ?? e.newValue,
    changedBy:     e.changed_by    || e.changedBy,
    changedAt:     e.changed_at    || e.changedAt,
    detectedAt:    e.detected_at   || e.detectedAt,
    ruleViolated:  e.rule_violated ?? e.ruleViolated,
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

function normalizePlaybook(p) {
  return {
    portalSteps:     p.portal_steps     || p.portalSteps     || [],
    cliCommands:     p.cli_commands     || p.cliCommands     || [],
    validationSteps: p.validation_steps || p.validationSteps || [],
    references:      p.references       || [],
  };
}

function normalizeComplianceFramework(data, id, color) {
  return {
    id,
    name:          data.framework,
    version:       data.version,
    score:         data.score_percent,
    totalControls: data.total_controls,
    passing:       data.passed,
    failing:       data.failed,
    notApplicable: (data.total_controls || 0) - (data.passed || 0) - (data.failed || 0),
    lastAssessed:  new Date().toISOString(),
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

// Display names must match ComparisonChart's COLORS keys exactly
const FW_DISPLAY = { cis: 'CIS Azure', nist: 'NIST SP 800-53', iso27001: 'ISO 27001', soc2: 'SOC 2 Type II' };

function buildComplianceFromFrameworks(cis, nist, iso, soc2, scans = []) {
  const frameworks = [
    normalizeComplianceFramework(cis,  'cis',      '#3b82f6'),
    normalizeComplianceFramework(nist, 'nist',     '#8b5cf6'),
    normalizeComplianceFramework(iso,  'iso27001', '#10b981'),
    normalizeComplianceFramework(soc2, 'soc2',     '#f59e0b'),
  ];

  // Build trend from scan history: scale each framework's failure count proportionally
  // to how many findings each historical scan had vs. the latest.
  const history = scans.filter((s) => (s.total_findings || 0) > 0).slice(0, 8).reverse();
  const latestCount = history.length > 0 ? (history[history.length - 1].total_findings || 1) : 1;

  const trend = history.length > 1
    ? history.map((s) => {
        const ratio = (s.total_findings || latestCount) / latestCount;
        const entry = {
          month: new Date(s.started_at || s.startedAt).toLocaleDateString(undefined, {
            month: 'short', day: 'numeric',
          }),
        };
        frameworks.forEach((fw) => {
          const total   = fw.totalControls || 1;
          const histFail = Math.round((fw.failing || 0) * ratio);
          entry[FW_DISPLAY[fw.id]] = Math.round(
            Math.max(0, Math.min(100, ((total - histFail) / total) * 100))
          );
        });
        return entry;
      })
    : [];

  return {
    frameworks,
    controls: [
      ...(cis.controls  || []).map((c) => normalizeComplianceControl(c, cis.framework)),
      ...(nist.controls || []).map((c) => normalizeComplianceControl(c, nist.framework)),
      ...(iso.controls  || []).map((c) => normalizeComplianceControl(c, iso.framework)),
      ...(soc2.controls || []).map((c) => normalizeComplianceControl(c, soc2.framework)),
    ],
    trend,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────
export const api = {

  getApiBase: () => API_BASE,

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
  health: async () => {
    try { const r = await fetch(`${API_BASE}/health`); return r.ok ? r.json() : null; }
    catch { return null; }
  },

  // ── Score  GET /api/score ──────────────────────────────────────────────────
  getScore: async () => normalizeScore(await apiFetch('/score')),

  // ── CVE Summary  GET /api/score/cve-summary ───────────────────────────────
  getCVESummary: async () => {
    try { return await apiFetch('/score/cve-summary'); }
    catch { return null; }
  },

  // ── Findings  GET /api/findings ────────────────────────────────────────────
  getFindings: async (filters = {}) => {
    const params = new URLSearchParams(Object.entries(filters).filter(([, v]) => v != null && v !== ''));
    const data = await apiFetch(`/findings${params.toString() ? '?' + params : ''}`);
    return (data.findings || data).map(normalizeFinding);
  },

  // ── Single finding  GET /api/findings/:id ─────────────────────────────────
  getFinding: async (id) => normalizeFinding(await apiFetch(`/findings/${id}`)),

  // ── Playbook  GET /api/findings/:id/playbook ───────────────────────────────
  getPlaybook: async (id) => {
    try { return normalizePlaybook(await apiFetch(`/findings/${id}/playbook`)); }
    catch { return { portalSteps: [], cliCommands: [], validationSteps: [], references: [] }; }
  },

  // ── Resources (Discovery)  GET /api/resources ─────────────────────────────
  getResources: async () => normalizeResourcesResponse(await apiFetch('/resources')),
  getResourceSummary: async () => { const d = await api.getResources(); return d.summary; },

  // ── Prioritization  GET /api/prioritization ────────────────────────────────
  getPrioritization: async () => normalizePrioritizationResponse(await apiFetch('/prioritization')),
  getPriorityMatrix: async () => { const d = await api.getPrioritization(); return d.matrix; },
  getRiskRankings:   async () => { const d = await api.getPrioritization(); return d.rankings; },

  // ── Drift  GET /api/drift ──────────────────────────────────────────────────
  getDrift: async () => normalizeDriftResponse(await apiFetch('/drift')),
  getDriftEvents: async () => { const d = await api.getDrift(); return d.events; },

  // ── Scans  GET /api/scans ──────────────────────────────────────────────────
  getScans: async () => normalizeScans(await apiFetch('/scans')),

  // ── Trigger scan  POST /api/scans/trigger ─────────────────────────────────
  triggerScan: async (subscriptionId) => apiFetch('/scans/trigger', {
    method: 'POST',
    body: JSON.stringify(subscriptionId ? { subscription_id: subscriptionId } : {}),
  }),

  // ── Single scan  GET /api/scans/:id (falls back to list) ──────────────────
  getScan: async (scanId) => {
    try { return await apiFetch(`/scans/${scanId}`); }
    catch {
      const data = await apiFetch('/scans');
      return normalizeScans(data).scans.find((s) => s.scan_id === scanId) ?? null;
    }
  },

  // ── Compliance  GET /api/compliance/<framework> ────────────────────────────
  getComplianceCIS:      async () => apiFetch('/compliance/cis'),
  getComplianceNIST:     async () => apiFetch('/compliance/nist'),
  getComplianceISO27001: async () => apiFetch('/compliance/iso27001'),
  getComplianceSOC2:     async () => apiFetch('/compliance/soc2'),

  getCompliance: async () => {
    const [cis, nist, iso, soc2, scansRaw] = await Promise.all([
      apiFetch('/compliance/cis'),
      apiFetch('/compliance/nist'),
      apiFetch('/compliance/iso27001'),
      apiFetch('/compliance/soc2'),
      apiFetch('/scans'),
    ]);
    return buildComplianceFromFrameworks(cis, nist, iso, soc2, normalizeScans(scansRaw).scans);
  },
  getFrameworks: async () => { const d = await api.getCompliance(); return d.frameworks; },

  // ── JWT helpers ────────────────────────────────────────────────────────────
  setToken,
  getToken,
};

export default api;
