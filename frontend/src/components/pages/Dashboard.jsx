import { useEffect, useState } from 'react'
import { api } from '../../services/api'
import { mockData } from '../../services/mockData'
import ScoreCard from '../ScoreCard'
import StatCard from '../StatCard'
import FindingsList from '../FindingList'
import CompliancePreview from '../CompliancePreview'

function Dashboard() {
  const [score, setScore] = useState(null)
  const [findings, setFindings] = useState([])
  const [lastScan, setLastScan] = useState(null)
  const [compliance, setCompliance] = useState(null)  // ← ADD THIS
  const [loading, setLoading] = useState(true)
  const [isDemo, setIsDemo] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [scoreData, findingsData, scansData, cisData, nistData, isoData] = await Promise.all([
          api.getScore(),
          api.getFindings({ limit: 5 }),
          api.getScans(),
          api.getComplianceCIS(),    
          api.getComplianceNIST(),  
          api.getComplianceISO(),     
        ])
        
        setScore(scoreData)
        setFindings(findingsData.findings)
        setLastScan(scansData.scans[0] || null)
        setCompliance({              
          cis: cisData,
          nist: nistData,
          iso: isoData,
        })
        setIsDemo(false)
      } catch (error) {
        console.log('Using demo data:', error.message)
        setScore(mockData.score)
        setFindings(mockData.findings.findings.slice(0, 5))
        setLastScan(mockData.scans.scans[0] || null)
        setCompliance({               
          cis: mockData.complianceCIS,
          nist: mockData.complianceNIST,
          iso: mockData.complianceISO,
        })
        setIsDemo(true)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-text-gray font-mono text-lg">Loading dashboard...</div>
      </div>
    )
  }

  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  const stats = [
    {
      label: 'Total Issues',
      value: findings.length,
      description: 'Security findings',
      color: 'tan',
    },
    {
      label: 'High Severity',
      value: severityCounts.HIGH || 0,
      description: 'Fix NOW',
      color: 'critical',
    },
    {
      label: 'Medium',
      value: severityCounts.MEDIUM || 0,
      description: 'Important',
      color: 'high',
    },
    {
      label: 'Low',
      value: severityCounts.LOW || 0,
      description: 'Minor',
      color: 'sage',
    },
  ]

  const getScanDuration = (scan) => {
    if (!scan.started_at || !scan.completed_at) return null
    const start = new Date(scan.started_at)
    const end = new Date(scan.completed_at)
    const minutes = Math.round((end - start) / 1000 / 60)
    return `${minutes}m`
  }

  return (
    <div className="max-w-7xl mx-auto p-8 space-y-20">
      {/* Demo Banner */}
      {isDemo && (
        <div className="bg-tan/20 border-2 border-tan px-6 py-4 rounded">
          <div className="flex items-center justify-between flex-wrap gap-4">
            <div>
              <div className="text-dark-brown font-mono text-sm font-bold mb-1">
                ⚠️ Demo Mode - Sample Data Only
              </div>
              <div className="text-text-gray font-mono text-sm">
                You're viewing fake data. Install OpenShield locally to scan your Azure.
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Header with Last Scan Info */}
      <div>
        <h1 className="text-dark-brown font-mono text-3xl font-bold mb-2">
          Security Dashboard
        </h1>
        {lastScan && (
          <p className="text-text-gray font-mono text-sm">
            Last scan: {new Date(lastScan.started_at).toLocaleString()}
            {lastScan.completed_at && ` • Completed in ${getScanDuration(lastScan)}`}
            {' • '}{lastScan.total_findings} findings
          </p>
        )}
      </div>

      {/* Score Card with Circular Progress */}
      {score && <ScoreCard score={score.score} maxScore={score.max_score} />}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {stats.map((stat, index) => (
          <StatCard
            key={index}
            label={stat.label}
            value={stat.value}
            description={stat.description}
            color={stat.color}
          />
        ))}
      </div>

      {/* Compliance Preview - NEW! */}
      {compliance && <CompliancePreview complianceData={compliance} />}

      {/* Recent Findings */}
      <FindingsList 
        findings={findings} 
        title="Recent Findings (Top 5)"
        showViewAll={true}
      />
    </div>
  )
}

export default Dashboard