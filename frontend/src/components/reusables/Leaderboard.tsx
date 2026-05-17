import { useEffect, useState } from 'react'

function Leaderboard() {
  const [contributors, setContributors] = useState([])
  const [loading, setLoading] = useState(true)
  const [useSimulation, setUseSimulation] = useState(false)

  const simulatedContributors = [
    { login: 'Vishnu2707', avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=Vishnu', contributions: 127, html_url: 'https://github.com/Vishnu2707' },
    { login: 'TFT444', avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=TFT', contributions: 89, html_url: 'https://github.com/TFT444' },
    { login: 'parthrohit22', avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=Parth', contributions: 56, html_url: 'https://github.com/parthrohit22' },
    { login: 'ritiksah141', avatar_url: 'https://api.dicebear.com/7.x/avataaars/svg?seed=Ritik', contributions: 42, html_url: 'https://github.com/ritiksah141' },
  ]

  useEffect(() => {
    const fetchAllContributors = async () => {
      try {
        // List of branches to check
        const branches = [
          'main',
          'dev',
          'feat/react-dashboard',
          'feat/az-idn-003-v2',
          'feat/az-cmp-002-v2'
        ]

        // Map to store contributor data
        const contributorMap = new Map()

        // Fetch commits from each branch
        for (const branch of branches) {
          try {
            const response = await fetch(
              `https://api.github.com/repos/openshield-org/openshield/commits?sha=${branch}&per_page=100`
            )
            
            if (!response.ok) continue

            const commits = await response.json()
            
            // Count commits per author
            commits.forEach(commit => {
              if (!commit.author) return
              
              const login = commit.author.login
              const existing = contributorMap.get(login) || {
                login: login,
                avatar_url: commit.author.avatar_url,
                html_url: commit.author.html_url,
                contributions: 0
              }
              
              existing.contributions += 1
              contributorMap.set(login, existing)
            })
          } catch (err) {
            console.log(`Failed to fetch ${branch}:`, err.message)
          }
        }

        // Convert map to array and sort by contributions
        const contributorsList = Array.from(contributorMap.values())
          .sort((a, b) => b.contributions - a.contributions)

        console.log('Contributors from all branches:', contributorsList)

        if (contributorsList.length > 0) {
          setContributors(contributorsList)
          setUseSimulation(false)
        } else {
          setContributors(simulatedContributors)
          setUseSimulation(true)
        }
      } catch (error) {
        console.error('Error fetching contributors:', error)
        setContributors(simulatedContributors)
        setUseSimulation(true)
      } finally {
        setLoading(false)
      }
    }

    fetchAllContributors()
  }, [])

  if (loading) {
    return (
      <div className="bg-white border-2 border-dark-brown p-8 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
        <div className="text-center text-text-gray font-mono">Loading contributors...</div>
      </div>
    )
  }

  const top3 = contributors.slice(0, 3)
  const rest = contributors.slice(3)

  return (
    <div className="bg-white border-2 border-dark-brown p-8 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
      {useSimulation && (
        <div className="mb-4 bg-tan/20 border border-tan px-3 py-2 rounded text-center">
          <span className="text-dark-brown font-mono text-xs font-bold">
            📊 SIMULATION MODE - Showing demo data
          </span>
        </div>
      )}

      <h2 className="text-tan font-mono text-sm font-bold mb-6 uppercase tracking-wide">
        🏆 TOP CONTRIBUTORS
      </h2>
      <p className="text-text-gray font-mono text-sm mb-6">
        Built by security engineers and students who believe cloud security should be accessible to everyone.
      </p>

      {/* Podium */}
      <div className="grid grid-cols-3 gap-4 mb-8">
        {/* 2nd Place */}
        {top3[1] && (
          <div className="flex flex-col items-center">
            <div className="text-4xl mb-2">🥈</div>
            <img 
              src={top3[1].avatar_url} 
              alt={top3[1].login}
              className="w-16 h-16 rounded-full border-2 border-dark-brown mb-2 object-cover bg-sage/20"
            />
            <a 
              href={top3[1].html_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-dark-brown font-mono font-bold text-sm text-center hover:text-tan transition-colors"
            >
              {top3[1].login}
            </a>
            <div className="text-dark-brown font-mono font-bold text-2xl mt-2">
              {top3[1].contributions}
            </div>
            <div className="text-text-gray/60 font-mono text-xs">contributions</div>
          </div>
        )}

        {/* 1st Place */}
        {top3[0] && (
          <div className="flex flex-col items-center">
            <div className="text-5xl mb-2">🥇</div>
            <img 
              src={top3[0].avatar_url} 
              alt={top3[0].login}
              className="w-20 h-20 rounded-full border-2 border-dark-brown mb-2 object-cover bg-tan/20"
            />
            <a 
              href={top3[0].html_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-dark-brown font-mono font-bold text-base text-center hover:text-tan transition-colors"
            >
              {top3[0].login}
            </a>
            <div className="text-dark-brown font-mono font-bold text-3xl mt-2">
              {top3[0].contributions}
            </div>
            <div className="text-text-gray/60 font-mono text-xs">contributions</div>
          </div>
        )}

        {/* 3rd Place */}
        {top3[2] && (
          <div className="flex flex-col items-center">
            <div className="text-4xl mb-2">🥉</div>
            <img 
              src={top3[2].avatar_url} 
              alt={top3[2].login}
              className="w-16 h-16 rounded-full border-2 border-dark-brown mb-2 object-cover bg-dark-brown/10"
            />
            <a 
              href={top3[2].html_url}
              target="_blank"
              rel="noopener noreferrer"
              className="text-dark-brown font-mono font-bold text-sm text-center hover:text-tan transition-colors"
            >
              {top3[2].login}
            </a>
            <div className="text-dark-brown font-mono font-bold text-2xl mt-2">
              {top3[2].contributions}
            </div>
            <div className="text-text-gray/60 font-mono text-xs">contributions</div>
          </div>
        )}
      </div>

      {/* All Contributors List */}
      {rest.length > 0 && (
        <div className="border-t-2 border-dark-brown/10 pt-6">
          <h3 className="text-dark-brown font-mono text-sm font-bold mb-4 uppercase">
            All Contributors ({contributors.length})
          </h3>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {rest.map((contributor, index) => (
              <div 
                key={contributor.login}
                className="flex items-center gap-3 p-3 bg-cream/50 rounded border border-dark-brown/10 hover:border-tan transition-colors"
              >
                <div className="text-text-gray/60 font-mono text-sm font-bold w-8">
                  #{index + 4}
                </div>
                <img 
                  src={contributor.avatar_url} 
                  alt={contributor.login}
                  className="w-10 h-10 rounded-full border border-dark-brown object-cover"
                />
                <div className="flex-1">
                  <a 
                    href={contributor.html_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-dark-brown font-mono font-bold text-sm hover:text-tan transition-colors"
                  >
                    {contributor.login}
                  </a>
                </div>
                <div className="text-dark-brown font-mono font-bold text-sm">
                  {contributor.contributions}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CTA */}
      <div className="bg-sage/10 border-2 border-sage p-6 rounded text-center mt-8">
        <h3 className="text-dark-brown font-mono font-bold text-base mb-2">
          Want to see your name here?
        </h3>
        <p className="text-text-gray font-mono text-sm mb-4">
          OpenShield welcomes contributions! Add scanner rules, write docs, fix bugs, or improve the UI.
        </p>
        <a 
          href="https://github.com/openshield-org/openshield/blob/main/CONTRIBUTING.md"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-block bg-sage text-white font-mono font-bold px-6 py-3 hover:bg-sage/90 transition-colors"
        >
          Start Contributing →
        </a>
      </div>
    </div>
  )
}

export default Leaderboard