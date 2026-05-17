import { Link } from "react-router-dom";

function CompliancePreview({ complianceData }) {
  const frameworks = [
    {
      name: "CIS",
      subtitle: "Azure Benchmark",
      data: complianceData.cis,
      color: "tan",
      progressColor: "bg-tan",
      textColor: "text-tan",
    },
    {
      name: "NIST",
      subtitle: "Cybersecurity Framework",
      data: complianceData.nist,
      color: "sage",
      progressColor: "bg-sage",
      textColor: "text-sage",
    },
    {
      name: "ISO 27001",
      subtitle: "International Standard",
      data: complianceData.iso,
      color: "dark-brown",
      progressColor: "bg-dark-brown",
      textColor: "text-dark-brown",
    },
  ];

  return (
    <div className="bg-white border-2 border-dark-brown shadow-[4px_4px_0px_0px_rgba(92,79,74,0.2)] overflow-hidden">
      {/* Header */}
      <div className="bg-cream border-b-2 border-dark-brown px-6 py-4 flex items-center justify-between">
        <h2 className="text-dark-brown font-mono text-sm font-bold uppercase">
          Compliance Overview
        </h2>
        <Link
          to="/compliance"
          className="text-tan font-mono text-sm font-bold hover:underline"
        >
          View Details →
        </Link>
      </div>

      {/* Compliance Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 p-6">
        {frameworks.map((framework) => (
          <div
            key={framework.name}
            className="border-2 border-dark-brown/20 p-4 hover:border-tan transition-colors cursor-pointer"
          >
            <div className="flex items-start justify-between mb-3">
              <div>
                <div className="text-dark-brown font-mono text-base font-bold">
                  {framework.name}
                </div>
                <div className="text-text-gray/60 font-mono text-xs">
                  {framework.subtitle}
                </div>
              </div>
              <div
                className={`${framework.textColor} font-mono text-2xl font-bold`}
              >
                {framework.data?.score_percent || 0}%
              </div>
            </div>

            {/* Progress Bar */}
            <div className="w-full h-2 bg-cream rounded-full overflow-hidden mb-3">
              <div
                className={`h-full ${framework.progressColor} transition-all duration-500`}
                style={{ width: `${framework.data?.score_percent || 0}%` }}
              />
            </div>

            {/* Stats */}
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="text-success">
                ✓ {framework.data?.passed || 0} passed
              </span>
              <span className="text-critical">
                ✗ {framework.data?.failed || 0} failed
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default CompliancePreview;
