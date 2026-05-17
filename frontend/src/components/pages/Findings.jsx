import { useEffect, useState } from 'react'
import { api } from '../../services/api'
import { mockData } from '../../services/mockData'
import FindingsList from '../FindingList'

function Findings() {
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [isDemo, setIsDemo] = useState(true)
  
  const [selectedSeverity, setSelectedSeverity] = useState('ALL')
  const [selectedCategory, setSelectedCategory] = useState('ALL')
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    fetchFindings()
  }, [selectedSeverity, selectedCategory])

  const fetchFindings = async () => {
    setLoading(true)
    try {
      const params = {}
      if (selectedSeverity !== 'ALL') params.severity = selectedSeverity
      if (selectedCategory !== 'ALL') params.category = selectedCategory
      
      const data = await api.getFindings(params)
      setFindings(data.findings)
      setIsDemo(false)
    } catch (error) {
      console.log('Using demo data:', error.message)
      
      // Apply filters to mock data
      let mockFindings = mockData.findings.findings
      
      if (selectedSeverity !== 'ALL') {
        mockFindings = mockFindings.filter(f => f.severity === selectedSeverity)
      }
      
      if (selectedCategory !== 'ALL') {
        mockFindings = mockFindings.filter(f => f.category === selectedCategory)
      }
      
      setFindings(mockFindings)
      setIsDemo(true)
    } finally {
      setLoading(false)
    }
  }

  // Search filter
  const filteredFindings = findings.filter(finding => {
    if (!searchQuery) return true
    const query = searchQuery.toLowerCase()
    return (
      finding.rule_id.toLowerCase().includes(query) ||
      finding.rule_name.toLowerCase().includes(query) ||
      finding.resource_name.toLowerCase().includes(query)
    )
  })

  // Count by severity from ALL mock data (not filtered)
  const allFindings = mockData.findings.findings
  const severityCounts = allFindings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  const totalCount = filteredFindings.length

  return (
    <div className="max-w-7xl mx-auto p-8 space-y-8">
      {/* Demo Banner */}
      {isDemo && (
        <div className="bg-tan/20 border-2 border-tan px-6 py-4 rounded">
          <div className="text-dark-brown font-mono text-sm font-bold mb-1">
            ⚠️ Demo Mode - Sample Data Only
          </div>
          <div className="text-text-gray font-mono text-sm">
            You're viewing fake data. Install OpenShield locally to scan your Azure.
          </div>
        </div>
      )}

      {/* Header */}
      <div>
        <h1 className="text-dark-brown font-mono text-3xl font-bold mb-2">
          Security Findings
        </h1>
        {!loading && (
          <p className="text-text-gray font-mono text-sm">
            {totalCount} {totalCount === 1 ? 'finding' : 'findings'} detected
            {selectedSeverity !== 'ALL' && ` • Filtered by ${selectedSeverity} severity`}
            {selectedCategory !== 'ALL' && ` • Filtered by ${selectedCategory}`}
          </p>
        )}
      </div>

      {/* Filters Card */}
      <div className="bg-white border-2 border-dark-brown p-6 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
        <h2 className="text-tan font-mono text-sm font-bold mb-4 uppercase">
          Filters
        </h2>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Search */}
          <div>
            <label className="text-dark-brown font-mono text-xs font-bold mb-2 block uppercase">
              Search
            </label>
            <input
              type="text"
              placeholder="Rule ID, name, or resource..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full px-3 py-2 border-2 border-dark-brown/20 font-mono text-sm focus:border-tan focus:outline-none"
              disabled={loading}
            />
          </div>

          {/* Severity Filter */}
          <div>
            <label className="text-dark-brown font-mono text-xs font-bold mb-2 block uppercase">
              Severity
            </label>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full px-3 py-2 border-2 border-dark-brown/20 font-mono text-sm focus:border-tan focus:outline-none"
              disabled={loading}
            >
              <option value="ALL">All ({allFindings.length})</option>
              <option value="HIGH">High ({severityCounts.HIGH || 0})</option>
              <option value="MEDIUM">Medium ({severityCounts.MEDIUM || 0})</option>
              <option value="LOW">Low ({severityCounts.LOW || 0})</option>
            </select>
          </div>

          {/* Category Filter */}
          <div>
            <label className="text-dark-brown font-mono text-xs font-bold mb-2 block uppercase">
              Category
            </label>
            <select
              value={selectedCategory}
              onChange={(e) => setSelectedCategory(e.target.value)}
              className="w-full px-3 py-2 border-2 border-dark-brown/20 font-mono text-sm focus:border-tan focus:outline-none"
              disabled={loading}
            >
              <option value="ALL">All Categories</option>
              <option value="Storage">Storage</option>
              <option value="Network">Network</option>
              <option value="Identity">Identity</option>
              <option value="Database">Database</option>
              <option value="Compute">Compute</option>
              <option value="KeyVault">Key Vault</option>
            </select>
          </div>
        </div>

        {/* Active Filters Summary */}
        {(selectedSeverity !== 'ALL' || selectedCategory !== 'ALL' || searchQuery) && (
          <div className="mt-4 flex items-center gap-2 flex-wrap">
            <span className="text-text-gray font-mono text-xs">Active filters:</span>
            
            {selectedSeverity !== 'ALL' && (
              <button
                onClick={() => setSelectedSeverity('ALL')}
                className="bg-critical/10 border border-critical text-critical px-2 py-1 text-xs font-mono font-bold flex items-center gap-1 hover:bg-critical/20"
              >
                Severity: {selectedSeverity} ✕
              </button>
            )}
            
            {selectedCategory !== 'ALL' && (
              <button
                onClick={() => setSelectedCategory('ALL')}
                className="bg-sage/10 border border-sage text-sage px-2 py-1 text-xs font-mono font-bold flex items-center gap-1 hover:bg-sage/20"
              >
                Category: {selectedCategory} ✕
              </button>
            )}
            
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="bg-tan/10 border border-tan text-tan px-2 py-1 text-xs font-mono font-bold flex items-center gap-1 hover:bg-tan/20"
              >
                Search: "{searchQuery}" ✕
              </button>
            )}
            
            <button
              onClick={() => {
                setSelectedSeverity('ALL')
                setSelectedCategory('ALL')
                setSearchQuery('')
              }}
              className="text-text-gray font-mono text-xs underline hover:text-dark-brown ml-2"
            >
              Clear all
            </button>
          </div>
        )}
      </div>

      {/* Findings List */}
      {loading ? (
        <div className="bg-white border-2 border-dark-brown p-12 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)] text-center">
          <div className="text-text-gray font-mono text-lg">Loading findings...</div>
        </div>
      ) : filteredFindings.length === 0 ? (
        <div className="bg-white border-2 border-dark-brown p-12 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)] text-center">
          <h3 className="text-dark-brown font-mono text-xl font-bold mb-2">
            No findings match your filters
          </h3>
          <p className="text-text-gray font-mono text-sm">
            Try adjusting your search or filters
          </p>
        </div>
      ) : (
        <FindingsList 
          findings={filteredFindings}
          title={`${totalCount} ${totalCount === 1 ? 'Finding' : 'Findings'}`}
          showViewAll={false}
        />
      )}
    </div>
  )
}

export default Findings