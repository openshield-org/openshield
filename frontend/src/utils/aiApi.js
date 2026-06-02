import aiMockData from '../mockData/ai.json';
import cveMockData from '../mockData/cve.json';

const AI_BASE = '/api/ai';
const TIMEOUT = 20000;

async function fetchAI(path, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT);
  try {
    const res = await fetch(`${AI_BASE}${path}`, {
      ...options,
      signal: controller.signal,
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch {
    clearTimeout(timer);
    throw new Error('backend_unavailable');
  }
}

// ── Smart mock response generator ─────────────────────────────────────────────
function mockChat(question, contextFinding) {
  if (contextFinding) return mockFindingChat(contextFinding, question);
  const q = question.toLowerCase();

  if (/crit|urgent|most important|highest|top|worst/.test(q)) {
    return {
      answer: "Your most critical findings right now are:\n\n1. **AZ-NET-001** — nsg-web has SSH (port 22) open to 0.0.0.0/0. Actively exploitable, no authentication required.\n2. **AZ-NET-007** — nsg-app has RDP (port 3389) open to 0.0.0.0/0. Top ransomware entry point.\n3. **AZ-DB-001** — sql-dev-exposed has a firewall rule allowing all IPs (0.0.0.0–255.255.255.255). Your database is reachable from the entire internet.\n\nAll three can be fixed in under 2 hours with very low effort. Start there.",
      sources: [
        { id: 'AZ-NET-001', resource: 'nsg-web' },
        { id: 'AZ-NET-007', resource: 'nsg-app' },
        { id: 'AZ-DB-001',  resource: 'sql-dev-exposed' },
      ],
    };
  }

  if (/ssh|rdp|port|network|nsg/.test(q)) {
    return {
      answer: "Network security findings: **nsg-web** allows SSH from 0.0.0.0/0 (AZ-NET-001) and **nsg-app** allows RDP from 0.0.0.0/0 (AZ-NET-007). To fix both:\n\n**CLI:**\n```\naz network nsg rule delete --resource-group rg-prod --nsg-name nsg-web --name Allow-SSH-Any\naz network nsg rule delete --resource-group rg-prod --nsg-name nsg-app --name Allow-RDP-Any\n```\n\nThen add rules restricted to your VPN CIDR (e.g. 10.0.0.0/8). Consider Azure Bastion as a long-term replacement for direct SSH/RDP access.",
      sources: [
        { id: 'AZ-NET-001', resource: 'nsg-web' },
        { id: 'AZ-NET-007', resource: 'nsg-app' },
      ],
    };
  }

  if (/storage|blob|public|https/.test(q)) {
    return {
      answer: "Storage findings: **prod-storage-01** has public blob access enabled (AZ-STOR-001) — anyone on the internet can read files. **staging-storage-01** doesn't enforce HTTPS (AZ-STOR-002). Fix both in under a minute:\n\n```\naz storage account update --name prod-storage-01 --resource-group rg-prod --allow-blob-public-access false\naz storage account update --name staging-storage-01 --resource-group rg-staging --https-only true\n```",
      sources: [
        { id: 'AZ-STOR-001', resource: 'prod-storage-01' },
        { id: 'AZ-STOR-002', resource: 'staging-storage-01' },
      ],
    };
  }

  if (/compli|cis|nist|iso|soc/.test(q)) {
    return {
      answer: "Your compliance scores: CIS Azure 74%, NIST SP 800-53 68%, ISO 27001 81%, SOC 2 77%. The biggest gap is NIST at 68% — it's failing 24 of 110 controls, primarily around access enforcement (AC-3, AC-6) and transmission confidentiality (SC-8). Fixing the 12 HIGH severity findings would push your CIS score from 74% to approximately 85%.",
      sources: [
        { id: 'CIS-6.2',   resource: 'nsg-web' },
        { id: 'NIST-AC-3', resource: 'prod-storage-01' },
        { id: 'NIST-SC-8', resource: 'staging-storage-01' },
      ],
    };
  }

  if (/drift|chang|modif|detect/.test(q)) {
    return {
      answer: "4 HIGH-severity drift events in the last 48 hours:\n\n• **prod-storage-01** — public blob access changed from false → true by john.doe at 14:32 (→ AZ-STOR-001)\n• **nsg-web** — SSH source changed from 10.0.0.0/8 → 0.0.0.0/0 by jane.smith at 11:15 (→ AZ-NET-001)\n• **staging-storage-01** — HTTPS disabled by john.doe at 16:45 (→ AZ-STOR-002)\n• **sql-dev-exposed** — AllowAllIPs firewall rule added by dev-team at 14:00 (→ AZ-DB-001)\n\nAll four created active HIGH-severity findings. The nsg-web change is the most dangerous — it immediately opened SSH to the internet.",
      sources: [
        { id: 'AZ-STOR-001', resource: 'prod-storage-01' },
        { id: 'AZ-NET-001',  resource: 'nsg-web' },
      ],
    };
  }

  if (/resource|multiple|most issue/.test(q)) {
    return {
      answer: "Resources with the most findings:\n\n1. **prod-storage-01** — 2 findings (AZ-STOR-001, AZ-STOR-003)\n2. **prod-storage-02** — 3 findings (lifecycle, backup, versioning)\n3. **nsg-staging** — 2 findings (permissive rules + flow logs)\n4. **cosmos-staging** — 2 findings (network ACL + public access)\n5. **kv-prod-secrets** — 2 findings (purge protection + network ACL)\n6. **vm-app-01** — 2 findings (disk encryption + antimalware)\n\nFocusing on prod-storage-01 first gives you the most security improvement per action since it's a production resource with HIGH risk.",
      sources: [
        { id: 'AZ-STOR-001', resource: 'prod-storage-01' },
        { id: 'AZ-STOR-003', resource: 'prod-storage-02' },
      ],
    };
  }

  return {
    answer: "I can help with that. Your environment has 136 open findings across 247 Azure resources — 12 HIGH, 35 MEDIUM, and 89 LOW severity. The fastest way to improve your security posture is to close the 3 CRITICAL network/database exposures (SSH on nsg-web, RDP on nsg-app, SQL firewall on sql-dev-exposed). Ask me about any specific finding, resource, or compliance question.",
    sources: [],
  };
}

function mockFindingChat(finding, question) {
  const q = question.toLowerCase();
  if (/fix|remediat|how|step/.test(q)) {
    const portal = finding.portalSteps?.[0] ?? 'Navigate to the resource in the Azure Portal.';
    const cli = finding.cliCommands?.[0] ?? 'See the Scan page for the full CLI playbook.';
    return {
      answer: `To remediate **${finding.ruleId}** on \`${finding.resourceName}\`:\n\n**Portal:** ${portal}\n\n**CLI:**\n\`\`\`\n${cli}\n\`\`\`\n\n**Validate:** ${finding.validationSteps?.[0] ?? 'Check Azure Security Center for the resolved recommendation.'}`,
      sources: [{ id: finding.ruleId, resource: finding.resourceName }],
    };
  }
  if (/risk|why|impact|danger/.test(q)) {
    return {
      answer: `**${finding.ruleId}** is rated **${finding.severity}** because ${finding.description.charAt(0).toLowerCase() + finding.description.slice(1)} References: ${finding.references?.join(', ')}.`,
      sources: [{ id: finding.ruleId, resource: finding.resourceName }],
    };
  }
  if (/validat|verify|confirm|test/.test(q)) {
    const steps = finding.validationSteps ?? ['Check the Azure Portal for the updated configuration.'];
    return {
      answer: `Validation steps for **${finding.ruleId}** on \`${finding.resourceName}\`:\n\n${steps.map((s, i) => `${i + 1}. ${s}`).join('\n')}`,
      sources: [{ id: finding.ruleId, resource: finding.resourceName }],
    };
  }
  return {
    answer: `**${finding.ruleId} — ${finding.ruleName}** on \`${finding.resourceName}\`:\n\n${finding.description}\n\n**Recommended action:** ${finding.remediation}`,
    sources: [{ id: finding.ruleId, resource: finding.resourceName }],
  };
}

// ── Public API ─────────────────────────────────────────────────────────────────
export const aiApi = {
  chat: async ({ question, contextFinding }) => {
    try {
      return await fetchAI('/chat', {
        method: 'POST',
        body: JSON.stringify({ question, context: contextFinding }),
      });
    } catch {
      return mockChat(question, contextFinding);
    }
  },

  getSummary: async () => {
    try {
      return await fetchAI('/summary');
    } catch {
      return aiMockData.executiveSummary;
    }
  },

  getCVEAnalysis: async () => {
    try {
      return await fetchAI('/cve-analysis');
    } catch {
      return cveMockData;
    }
  },
};
