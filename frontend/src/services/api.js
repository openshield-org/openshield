import API_BASE_URL, { API_ENDPOINTS } from '../config/api'

const getToken = () => localStorage.getItem('jwt_token')

const apiFetch = async (endpoint, options = {}) => {
  const token = getToken()
  
  const headers = {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token}` }),
    ...options.headers,
  }

  const response = await fetch(`${API_BASE_URL}${endpoint}`, {
    ...options,
    headers,
  })

  if (!response.ok) {
    throw new Error(`API Error: ${response.status}`)
  }

  return response.json()
}

export const api = {
  health: () => apiFetch(API_ENDPOINTS.health),
  getFindings: (params = {}) => {
    const query = new URLSearchParams(params).toString()
    return apiFetch(`${API_ENDPOINTS.findings}${query ? `?${query}` : ''}`)
  },
  getFindingById: (id) => apiFetch(API_ENDPOINTS.findingDetail(id)),
  getScore: () => apiFetch(API_ENDPOINTS.score),
  getScans: () => apiFetch(API_ENDPOINTS.scans),
  triggerScan: (subscriptionId) => 
    apiFetch(API_ENDPOINTS.triggerScan, {
      method: 'POST',
      body: JSON.stringify({ subscription_id: subscriptionId }),
    }),
  getComplianceCIS: () => apiFetch(API_ENDPOINTS.complianceCIS),
  getComplianceNIST: () => apiFetch(API_ENDPOINTS.complianceNIST),
  getComplianceISO: () => apiFetch(API_ENDPOINTS.complianceISO),
}