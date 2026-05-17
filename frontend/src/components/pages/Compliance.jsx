import { useEffect, useState } from 'react'
import { api } from '../../services/api'
import { mockData } from '../../services/mockData'

function Compliance() {
  const [frameworks, setFrameworks] = useState({
    cis: null,
    nist: null,
    iso: null,
  })
  const [loading, setLoading] = useState(true)
  const [isDemo, setIsDemo] = useState(true)
  const [selectedFramework, setSelectedFramework] = useState('cis')

  useEffect(() => {
    fetchCompliance()
  }, [])

  const fetchCompliance = async () => {
    setLoading(true)
    try {
      const [cisData, nistData, isoData] = await Promise.all([
        api.getComplianceCIS(),
        api.getComplianceNIST(),
        api.getComplianceISO(),
      ])

      setFrameworks({
        cis: cisData,
        nist: nistData,
        iso: isoData,
      })
      setIsDemo(false)
    } catch (error) {
      console.log('Using demo data:', error.message)
      setFrameworks({
        cis: mockData.complianceCIS,
        nist: mockData.complianceNIST,
        iso: mockData.complianceISO,
      })
      setIsDemo(true)
    } finally {
      setLoading(false)
    }
  }

  const frameworkConfigs = {
    cis: {
      key: 'cis',
      name: 'CIS',
      fullName: 'CIS Microsoft Azure Foundations Benchmark',
      color: 'tan',
      bgColor: 'bg-tan',
      textColor: 'text-tan',
      description: 'Industry-standard security baseline for Azure environments',
    },
    nist: {
      key: 'nist',
      name: 'NIST',
      fullName: 'NIST Cybersecurity Framework',
      color: 'sage',
      bgColor: 'bg-sage',
      textColor: 'text-sage',
      description: 'U.S. government cybersecurity standard',
    },
    iso: {
      key: 'iso',
      name: 'ISO 27001',
      fullName: 'ISO/IEC 27001:2013',
      color: 'dark-brown',
      bgColor: 'bg-dark-brown',
      textColor: 'text-dark-brown',
      description: 'International information security management standard',
    },
  }

  const activeFramework = frameworks[selectedFramework]
  const config = frameworkConfigs[selectedFramework]

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto p-8 space-y-8">
        <div className="flex items-center justify-center min-h-[60vh]">
          <div className="text-text-gray font-mono text-lg">Loading compliance data...</div>
        </div>
      </div>
    )
  }

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
          Compliance Frameworks
        </h1>
        <p className="text-text-gray font-mono text-sm">
          Track your Azure security posture against industry standards
        </p>
      </div>

      {/* Framework Tabs */}
      <div className="flex gap-4 border-b-2 border-dark-brown/20">
        {Object.values(frameworkConfigs).map((fw) => (
          <button
            key={fw.key}
            onClick={() => setSelectedFramework(fw.key)}
            className={`px-6 py-3 font-mono font-bold text-sm transition-colors border-b-2 -mb-[2px] ${
              selectedFramework === fw.key
                ? `${fw.textColor} border-${fw.color}`
                : 'text-text-gray/60 border-transparent hover:text-dark-brown'
            }`}
          >
            {fw.name}
          </button>
        ))}
      </div>

      {/* Framework Overview Card */}
      <div className="bg-white border-2 border-dark-brown p-8 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
        <div className="flex items-start justify-between mb-6">
          <div>
            <h2 className="text-dark-brown font-mono text-2xl font-bold mb-2">
              {config.fullName}
            </h2>
            <p className="text-text-gray font-mono text-sm mb-1">
              {config.description}
            </p>
            {activeFramework?.version && (
              <p className="text-text-gray/60 font-mono text-xs">
                Version {activeFramework.version}
              </p>
            )}
          </div>
          <div className={`${config.textColor} font-mono text-5xl font-bold`}>
            {activeFramework?.score_percent || 0}%
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full h-4 bg-cream rounded-full overflow-hidden mb-6">
          <div
            className={`h-full ${config.bgColor} transition-all duration-1000`}
            style={{ width: `${activeFramework?.score_percent || 0}%` }}
          />
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-3 gap-6">
          <div className="text-center">
            <div className="text-text-gray/60 font-mono text-xs font-bold uppercase mb-2">
              Total Controls
            </div>
            <div className="text-dark-brown font-mono text-3xl font-bold">
              {activeFramework?.total_controls || 0}
            </div>
          </div>
          <div className="text-center">
            <div className="text-text-gray/60 font-mono text-xs font-bold uppercase mb-2">
              Passed
            </div>
            <div className="text-success font-mono text-3xl font-bold">
              {activeFramework?.passed || 0}
            </div>
          </div>
          <div className="text-center">
            <div className="text-text-gray/60 font-mono text-xs font-bold uppercase mb-2">
              Failed
            </div>
            <div className="text-critical font-mono text-3xl font-bold">
              {activeFramework?.failed || 0}
            </div>
          </div>
        </div>
      </div>

      {/* Controls List */}
      {activeFramework?.controls && activeFramework.controls.length > 0 ? (
        <div className="bg-white border-2 border-dark-brown shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)] overflow-hidden">
          <div className="bg-cream border-b-2 border-dark-brown px-6 py-4">
            <h3 className="text-dark-brown font-mono text-sm font-bold uppercase">
              Controls ({activeFramework.controls.length})
            </h3>
          </div>

          <div className="divide-y-2 divide-cream">
            {activeFramework.controls.map((control, index) => (
              <div
                key={index}
                className="p-6 hover:bg-cream/50 transition-colors"
              >
                <div className="flex items-start gap-4">
                  {/* Status Badge */}
                  <div
                    className={`px-3 py-1 rounded font-mono text-xs font-bold ${
                      control.status === 'PASS'
                        ? 'bg-success text-white'
                        : 'bg-critical text-white'
                    }`}
                  >
                    {control.status === 'PASS' ? '✓ PASS' : '✗ FAIL'}
                  </div>

                  {/* Control Info */}
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="text-text-gray/60 font-mono text-xs font-bold">
                        {control.control_id}
                      </span>
                      {control.rule_id && (
                        <span className="text-text-gray/60 font-mono text-xs">
                          → {control.rule_id}
                        </span>
                      )}
                    </div>
                    <h4 className="text-dark-brown font-mono font-bold text-base">
                      {control.control_name}
                    </h4>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="bg-white border-2 border-dark-brown p-12 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)] text-center">
          <div className="text-text-gray font-mono text-sm">
            No control details available for this framework
          </div>
        </div>
      )}
    </div>
  )
}

export default Compliance