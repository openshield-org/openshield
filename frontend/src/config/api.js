const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5001'

export const API_ENDPOINTS = {
  health: '/health',
  findings: '/api/findings',
  findingDetail: (id) => `/api/findings/${id}`,
  score: '/api/score',
  scans: '/api/scans',
  triggerScan: '/api/scans/trigger',
  complianceCIS: '/api/compliance/cis',
  complianceNIST: '/api/compliance/nist',
  complianceISO: '/api/compliance/iso27001',
}

export default API_BASE_URL