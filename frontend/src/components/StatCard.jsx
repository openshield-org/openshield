function StatCard({ label, value, description, color = 'tan' }) {
  const colorClasses = {
    tan: 'text-tan',
    critical: 'text-critical',
    high: 'text-high',
    sage: 'text-sage',
    'dark-brown': 'text-dark-brown',
  }

  const labelColorClass = colorClasses[color] || 'text-tan'
  const valueColorClass = color === 'tan' ? 'text-dark-brown' : colorClasses[color]

  return (
    <div className=" text-center bg-white border-2 border-dark-brown p-6 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
      <div className={`${labelColorClass} font-mono text-md font-bold mb-2 uppercase`}>
        {label}
      </div>
      <div className={`${valueColorClass} font-mono text-4xl font-bold`}>
        {value}
      </div>
      <div className="text-text-gray font-mono text-xs mt-2">
        {description}
      </div>
    </div>
  )
}

export default StatCard