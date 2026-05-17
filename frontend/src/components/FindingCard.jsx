function FindingCard({ finding }) {
  const severityColors = {
    HIGH: 'bg-critical',
    MEDIUM: 'bg-high',
    LOW: 'bg-sage',
    INFO: 'bg-dark-brown',
  }

  const badgeColor = severityColors[finding.severity] || 'bg-sage'

  // Format date
  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    })
  }

  return (
    <div className="p-6 border-b-2 border-cream hover:bg-cream/50 transition-colors cursor-pointer">
      <div className="flex items-start gap-4">
        {/* Severity Badge */}
        <div className={`${badgeColor} text-white px-3 py-1 rounded font-mono text-xs font-bold`}>
          {finding.severity}
        </div>

        {/* Finding Info */}
        <div className="flex-1">
          {/* Rule ID */}
          <div className="text-text-gray/60 font-mono text-xs mb-2">
            {finding.rule_id}
          </div>

          {/* Rule Name */}
          <h3 className="text-dark-brown font-mono font-bold text-base mb-2">
            {finding.rule_name}
          </h3>

          {/* Resource */}
          <div className="text-text-gray font-mono text-sm mb-3">
            <strong>Resource:</strong> {finding.resource_name} ({finding.category})
          </div>

          {/* Description */}
          <p className="text-text-gray/80 font-mono text-sm mb-3">
            {finding.description}
          </p>

          {/* Remediation */}
          {finding.remediation && (
            <div className="bg-sage/10 border-l-4 border-sage px-3 py-2 mb-3">
              <div className="text-sage font-mono text-xs font-bold mb-1">
                HOW TO FIX:
              </div>
              <div className="text-text-gray font-mono text-sm">
                {finding.remediation}
              </div>
            </div>
          )}

          {/* Detected At */}
          <div className="text-text-gray/60 font-mono text-xs">
            Detected: {formatDate(finding.detected_at)}
          </div>
        </div>
      </div>
    </div>
  )
}

export default FindingCard