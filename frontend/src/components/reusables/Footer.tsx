function Footer() {
  const currentYear = new Date().getFullYear()

  // Easy to edit links object
  const footerLinks = {
    product: [
      { name: 'Dashboard', url: '/' },
      { name: 'Findings', url: '/findings' },
      { name: 'Compliance', url: '/compliance' },
      { name: 'Documentation', url: 'https://github.com/openshield-org/openshield#quick-start', external: true },
    ],
    community: [
      { name: 'GitHub', url: 'https://github.com/openshield-org/openshield', external: true },
      { name: 'Discord', url: 'https://discord.gg/your-server', external: true },
      { name: 'Contributing', url: 'https://github.com/openshield-org/openshield/blob/main/CONTRIBUTING.md', external: true },
      { name: 'Issues', url: 'https://github.com/openshield-org/openshield/issues', external: true },
      { name: 'Contributors', url: '/about' },
    ],
    resources: [
      { name: 'About', url: 'https://github.com/openshield-org/openshield#readme', external: true },
      { name: 'License', url: 'https://github.com/openshield-org/openshield/blob/main/LICENSE', external: true },
      { name: 'Security', url: 'https://github.com/openshield-org/openshield/security', external: true },
      { name: 'Releases', url: 'https://github.com/openshield-org/openshield/releases', external: true },
    ],
  }

  return (
    <footer className="bg-cream border-t-2 border-dark-brown/20 mt-16">
      <div className="max-w-7xl mx-auto px-6 py-12">
        {/* Top Section */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8 mb-8">
          {/* Brand */}
          <div className="md:col-span-1">
            <div className="flex items-center gap-3 mb-4">
              <img src="/logo.svg" alt="OpenShield" className="w-8 h-8" />
              <span className="text-dark-brown font-mono text-lg font-bold">OPENSHIELD</span>
            </div>
            <p className="text-text-gray font-mono text-sm leading-relaxed">
              Open source cloud security for everyone. Built by the community, for the community.
            </p>
          </div>

          {/* Product */}
          <div>
            <h3 className="text-tan font-mono text-sm font-bold mb-4 uppercase">Product</h3>
            <ul className="space-y-2">
              {footerLinks.product.map((link) => (
                <li key={link.name}>
                  <a 
                    href={link.url}
                    {...(link.external && { target: '_blank', rel: 'noopener noreferrer' })}
                    className="text-text-gray hover:text-tan font-mono text-sm transition-colors"
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Community */}
          <div>
            <h3 className="text-tan font-mono text-sm font-bold mb-4 uppercase">Community</h3>
            <ul className="space-y-2">
              {footerLinks.community.map((link) => (
                <li key={link.name}>
                  <a 
                    href={link.url}
                    {...(link.external && { target: '_blank', rel: 'noopener noreferrer' })}
                    className="text-text-gray hover:text-tan font-mono text-sm transition-colors"
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Resources */}
          <div>
            <h3 className="text-tan font-mono text-sm font-bold mb-4 uppercase">Resources</h3>
            <ul className="space-y-2">
              {footerLinks.resources.map((link) => (
                <li key={link.name}>
                  <a 
                    href={link.url}
                    {...(link.external && { target: '_blank', rel: 'noopener noreferrer' })}
                    className="text-text-gray hover:text-tan font-mono text-sm transition-colors"
                  >
                    {link.name}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Divider */}
        <div className="border-t border-dark-brown/20 pt-8">
          <div className="flex flex-col md:flex-row justify-between items-center gap-4">
            {/* Copyright */}
            <div className="text-text-gray/60 font-mono text-sm">
              © {currentYear} OpenShield. MIT License.
            </div>

            {/* Tagline */}
            <div className="text-text-gray font-mono text-sm text-center">
              Built with love by the community · Made for everyone.
            </div>

            {/* Social/Stats */}
            <div className="flex items-center gap-4">
              <a 
                href="https://github.com/openshield-org/openshield" 
                target="_blank" 
                rel="noopener noreferrer"
                className="text-text-gray hover:text-tan font-mono text-sm transition-colors flex items-center gap-1"
              >
                ⭐ Star on GitHub
              </a>
            </div>
          </div>
        </div>
      </div>
    </footer>
  )
}

export default Footer