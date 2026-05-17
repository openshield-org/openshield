import Leaderboard from "../reusables/Leaderboard";
import Footer from "../reusables/Footer";

function About() {
  const topContributors = [
    {
      rank: 1,
      name: "Vishnu Ajith",
      username: "@Vishnu2707",
      contributions: 127,
      avatar: "VA",
    },
    {
      rank: 2,
      name: "TFT444",
      username: "@TFT444",
      contributions: 89,
      avatar: "TF",
    },
    {
      rank: 3,
      name: "Parth Rohit",
      username: "@parthrohit22",
      contributions: 56,
      avatar: "PR",
    },
  ];

  return (
    <div className="max-w-7xl mx-auto p-8 space-y-8">
      {/* Top Section - About & Demo Note */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
        {/* Left Card - About OpenShield */}
        <div className="bg-white border-2 border-dark-brown p-8 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
          <h2 className="text-tan font-mono text-sm font-bold mb-4 uppercase tracking-wide">
            OPEN SHIELD:
          </h2>
          <p className="text-text-gray font-mono text-base leading-relaxed mb-6">
            Open source Cloud Security Posture Management (CSPM) for Azure —
            built by the community, for the community.
          </p>
          <a
            href="https://github.com/openshield-org/openshield"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-block bg-sage text-white font-mono font-bold px-6 py-3 hover:bg-sage/90 transition-colors"
          >
            Github →
          </a>
        </div>

        {/* Right Card - Demo Note */}
        <div className="bg-white border-2 border-dark-brown p-8 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
          <h2 className="text-tan font-mono text-sm font-bold mb-4 uppercase tracking-wide">
            NOTE:
          </h2>
          <p className="text-text-gray font-mono text-base leading-relaxed">
            You're viewing a preview with fake data. To scan YOUR Azure
            subscription, install OpenShield locally and connect your
            credentials. Your real Azure data never touches this public site!
          </p>
        </div>
      </div>

      {/* Why OpenShield Exists */}
      <div className="bg-white border-2 border-dark-brown p-8 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
        <h2 className="text-tan font-mono text-sm font-bold mb-4 uppercase tracking-wide">
          THE PROBLEM:
        </h2>
        <p className="text-text-gray font-mono text-base leading-relaxed mb-4">
          Enterprise cloud security tools like Wiz, Prisma Cloud, and Microsoft
          Defender for Cloud cost{" "}
          <span className="font-bold">$50,000–$500,000/year</span>.
        </p>
        <p className="text-text-gray font-mono text-base leading-relaxed mb-4">
          Startups, SMEs, universities, and student teams are left with zero
          visibility into their Azure security posture. A misconfigured storage
          blob, an overprivileged service principal, or an open NSG rule can sit
          undetected for months.
        </p>
        <p className="text-text-gray font-mono text-base leading-relaxed font-bold">
          OpenShield changes that. Cloud security is a human right, not a
          luxury. 🚀
        </p>
      </div>

      {/* Features Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        <div className="bg-white border-2 border-dark-brown p-6 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
          <h3 className="text-tan font-mono text-sm font-bold mb-2 uppercase">
            🔍 Scanner
          </h3>
          <p className="text-text-gray font-mono text-sm">
            20+ Azure security rules across storage, network, identity,
            database, and compute
          </p>
        </div>

        <div className="bg-white border-2 border-dark-brown p-6 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
          <h3 className="text-tan font-mono text-sm font-bold mb-2 uppercase">
            📋 Compliance
          </h3>
          <p className="text-text-gray font-mono text-sm">
            Maps findings to CIS, NIST, ISO 27001, and SOC 2 frameworks
          </p>
        </div>

        <div className="bg-white border-2 border-dark-brown p-6 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
          <h3 className="text-tan font-mono text-sm font-bold mb-2 uppercase">
            🔧 Remediation
          </h3>
          <p className="text-text-gray font-mono text-sm">
            Every rule ships with Azure CLI playbooks to fix issues fast
          </p>
        </div>

        <div className="bg-white border-2 border-dark-brown p-6 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
          <h3 className="text-tan font-mono text-sm font-bold mb-2 uppercase">
            🆓 Free Forever
          </h3>
          <p className="text-text-gray font-mono text-sm">
            MIT License. Self-hosted. Your credentials never leave your machine.
          </p>
        </div>

        <div className="bg-white border-2 border-dark-brown p-6 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
          <h3 className="text-tan font-mono text-sm font-bold mb-2 uppercase">
            🛡️ Sentinel
          </h3>
          <p className="text-text-gray font-mono text-sm">
            Push findings to Microsoft Sentinel with KQL analytics rules
          </p>
        </div>

        <div className="bg-white border-2 border-dark-brown p-6 shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)]">
          <h3 className="text-tan font-mono text-sm font-bold mb-2 uppercase">
            📊 Dashboard
          </h3>
          <p className="text-text-gray font-mono text-sm">
            Security score, findings list, compliance view - all in one place
          </p>
        </div>
      </div>

      {/* Leaderboard */}
      <Leaderboard />
    </div>
  );
}

export default About;
