import { useState } from 'react'

const RiskBadge = ({ level, score }) => {
  const isMalicious = level === 'MALICIOUS' || level === 'HIGH RISK' || (score > 50);
  const isSuspicious = !isMalicious && (level === 'SUSPICIOUS' || score > 20);

  if (isMalicious) {
    return (
      <span className="badge badge-critical">
        <span className="w-1.5 h-1.5 rounded-full bg-red-400"></span>
        MALICIOUS
      </span>
    );
  }
  if (isSuspicious) {
    return (
      <span className="badge badge-suspicious">
        <span className="w-1.5 h-1.5 rounded-full bg-amber-400"></span>
        SUSPICIOUS
      </span>
    );
  }
  return (
    <span className="badge badge-safe">
      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
      SAFE
    </span>
  );
}

const SSLBadge = ({ status }) => {
  const isGood = status === 'VALID'
  const isBad = status === 'NO SSL' || status === 'INVALID' || status === 'EXPIRED'
  const color = isGood ? 'text-emerald-400' : isBad ? 'text-red-400' : 'text-slate-500'
  return (
    <span className={`font-mono text-xs ${color}`}>
      {isGood ? 'VALID' : isBad ? 'INSECURE' : 'UNKNOWN'}
    </span>
  )
}

const ScoreBar = ({ score }) => {
  const color = score > 50 ? 'bg-red-500 text-red-400' : score > 20 ? 'bg-amber-500 text-amber-400' : 'bg-emerald-500 text-emerald-400'
  const barColor = color.split(' ')[0]
  const textColor = color.split(' ')[1]

  return (
    <div className="flex items-center gap-2">
      <div className="w-12 h-1 bg-slate-800 rounded-full overflow-hidden">
        <div className={`h-full ${barColor}`} style={{ width: `${Math.min(100, score)}%` }}></div>
      </div>
      <span className={`font-mono text-xs font-semibold ${textColor}`}>{score}</span>
    </div>
  )
}

export default function ReportTable({ scans }) {
  const [expanded, setExpanded] = useState(null)

  if (!scans || scans.length === 0) {
    return (
      <div className="p-8 text-center text-slate-500 font-mono text-xs">
        [ NO RECENT DETECTIONS LOGGED ]
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="soc-table">
        <thead>
          <tr>
            <th>TARGET URL</th>
            <th>DOMAIN</th>
            <th>THREAT SCORE</th>
            <th>CLASSIFICATION</th>
            <th>SSL/TLS</th>
            <th>TIMESTAMP</th>
            <th className="text-right">DETAILS</th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => {
            const isExpanded = expanded === scan._id
            return (
              <tr key={scan._id || scan.url + scan.createdAt} className={isExpanded ? 'bg-slate-800/40' : ''}>
                <td className="max-w-[220px]">
                  <span className="text-slate-300 font-mono text-xs truncate block" title={scan.url}>
                    {scan.url}
                  </span>
                </td>
                <td>
                  <span className="text-slate-400 font-mono text-xs">{scan.domain}</span>
                </td>
                <td>
                  <ScoreBar score={scan.threatScore || 0} />
                </td>
                <td>
                  <RiskBadge level={scan.riskLevel} score={scan.threatScore} />
                </td>
                <td>
                  <SSLBadge status={scan.sslStatus?.status || (scan.sslStatus?.valid ? 'VALID' : 'NO SSL')} />
                </td>
                <td className="text-slate-500 font-mono text-[11px]">
                  {scan.createdAt ? new Date(scan.createdAt).toISOString().replace('T', ' ').slice(0, 16) : 'Just now'}
                </td>
                <td className="text-right">
                  <button 
                    onClick={() => setExpanded(isExpanded ? null : scan._id)}
                    className="text-sky-400 hover:text-white text-[11px] font-mono bg-sky-500/10 hover:bg-sky-500/20 px-2 py-0.5 rounded transition-colors"
                  >
                    {isExpanded ? '[-] CLOSE' : '[+] VIEW'}
                  </button>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
