import { Link } from 'react-router-dom'
import FindingCard from './FindingCard'

function FindingsList({ findings, title = 'Recent Findings', showViewAll = false }) {
  return (
    <div className="bg-white border-2 border-dark-brown shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)] overflow-hidden">
      {/* Header */}
      <div className="bg-cream border-b-2 border-dark-brown px-6 py-4 flex items-center justify-between">
        <h2 className="text-dark-brown font-mono text-sm font-bold uppercase">
          {title} ({findings.length})
        </h2>
        {showViewAll && (
          <Link to="/findings" className="text-tan font-mono text-sm font-bold hover:underline">
            View All →
          </Link>
        )}
      </div>

      {/* Findings List */}
      <div>
        {findings.length === 0 ? (
          <div className="p-8 text-center text-text-gray font-mono">
            No findings yet! 
          </div>
        ) : (
          findings.map((finding) => (
            <FindingCard key={finding.id} finding={finding} />
          ))
        )}
      </div>
    </div>
  )
}

export default FindingsList