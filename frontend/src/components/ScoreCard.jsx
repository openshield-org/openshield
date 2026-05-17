function ScoreCard({ score, maxScore }) {
  // Calculate percentage for the circular progress
  const percentage = (score / maxScore) * 100
  
  // SVG circle parameters
  const size = 280
  const strokeWidth = 24
  const radius = (size - strokeWidth) / 2
  const circumference = radius * 2 * Math.PI
  const offset = circumference - (percentage / 100) * circumference

  return (
    <div className="bg-white border-2 border-dark-brown p-12 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
      <h2 className="text-center text-dark-brown font-mono text-xl font-bold mb-8 uppercase tracking-wide">
        Overall Security Score
      </h2>
      
      <div className="flex justify-center items-center">
        <div className="relative" style={{ width: size, height: size }}>
          {/* SVG Circular Progress */}
          <svg
            width={size}
            height={size}
            className="transform -rotate-90"
          >
            {/* Background circle (gray) */}
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              stroke="#D1D5DB"
              strokeWidth={strokeWidth}
              fill="none"
            />
            
            {/* Progress circle (tan) */}
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              stroke="#C9996B"
              strokeWidth={strokeWidth}
              fill="none"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              strokeLinecap="round"
              className="transition-all duration-1000 ease-out"
            />
          </svg>
          
          {/* Score Text in Center */}
          <div className="absolute inset-0 flex items-center justify-center">
            <div className="text-center">
              <div className="font-mono text-6xl font-bold text-dark-brown">
                {score}<span className="text-4xl text-text-gray/40">/{maxScore}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <p className="text-center text-text-gray font-mono text-sm mt-8">
        Deducts 10pts per HIGH, 5pts per MEDIUM, 2pts per LOW finding
      </p>
    </div>
  )
}

export default ScoreCard