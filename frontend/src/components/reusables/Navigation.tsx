import { NavLink } from 'react-router-dom'
import { useState } from 'react'

function Navigation() {
  const [isMenuOpen, setIsMenuOpen] = useState(false)

  const navItems = [
    { name: 'Dashboard', path: '/' },
    { name: 'Findings', path: '/findings' },
    { name: 'Compliance', path: '/compliance' },
    { name: 'About', path: '/about' },
  ]

  return (
    <nav className="bg-cream border-b border-dark-brown/20">
      <div className="max-w-7xl mx-auto px-6 flex items-center justify-between h-16">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <img src="/logo.svg" alt="OpenShield" className="w-12 h-12" />
          <span className="text-dark-brown font-mono text-sm font-bold tracking-wide uppercase">
            Open Shield
          </span>
        </div>

        {/* Desktop Nav */}
        <div className="hidden md:flex gap-8">
          {navItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `font-mono text-sm font-bold transition-colors ${
                  isActive
                    ? 'text-dark-brown'
                    : 'text-dark-brown/60 hover:text-dark-brown'
                }`
              }
            >
              {item.name}
            </NavLink>
          ))}
        </div>

        {/* Mobile Menu Button */}
        <button
          onClick={() => setIsMenuOpen(!isMenuOpen)}
          className="md:hidden text-dark-brown"
        >
          <svg
            className="w-6 h-6"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            {isMenuOpen ? (
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M6 18L18 6M6 6l12 12"
              />
            ) : (
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M4 6h16M4 12h16M4 18h16"
              />
            )}
          </svg>
        </button>
      </div>

      {/* Mobile Menu */}
      {isMenuOpen && (
        <div className="md:hidden border-t border-dark-brown/20 bg-cream">
          <div className="px-6 py-4 flex flex-col gap-4">
            {navItems.map((item) => (
              <NavLink
                key={item.path}
                to={item.path}
                onClick={() => setIsMenuOpen(false)}
                className={({ isActive }) =>
                  `font-mono text-sm font-bold transition-colors ${
                    isActive
                      ? 'text-dark-brown'
                      : 'text-dark-brown/60 hover:text-dark-brown'
                  }`
                }
              >
                {item.name}
              </NavLink>
            ))}
          </div>
        </div>
      )}
    </nav>
  )
}

export default Navigation