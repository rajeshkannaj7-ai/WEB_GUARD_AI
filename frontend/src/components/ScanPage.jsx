import { useState, useRef, useEffect, useMemo, useCallback } from 'react'
import { scanUrl, getIPIntelligence } from '../services/api'
import ScanProgress from './ScanProgress'
import html2canvas from 'html2canvas'
import jsPDF from 'jspdf'

/**
 * Compact Threat Score Gauge (SVG)
 */
const ThreatScoreBadge = ({ score, riskLevel }) => {
  const isCritical = score > 50 || riskLevel === 'MALICIOUS' || riskLevel === 'HIGH RISK';
  const isSuspicious = !isCritical && (score > 20 || riskLevel === 'SUSPICIOUS');

  const strokeColor = isCritical ? '#EF4444' : isSuspicious ? '#F59E0B' : '#10B981';
  const textColor = isCritical ? 'text-red-400' : isSuspicious ? 'text-amber-400' : 'text-emerald-400';
  const radius = 28;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex items-center gap-3.5">
      <div className="relative w-16 h-16 shrink-0 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90">
          <circle cx="32" cy="32" r={radius} stroke="#1E293B" strokeWidth="5" fill="none" />
          <circle
            cx="32"
            cy="32"
            r={radius}
            stroke={strokeColor}
            strokeWidth="5"
            fill="none"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            className="transition-all duration-700 ease-out"
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className={`text-base font-mono font-bold ${textColor}`}>
            {score}
          </span>
        </div>
      </div>
      <div>
        <span className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider">
          Threat Score
        </span>
        <span className={`text-lg font-mono font-bold leading-tight ${textColor}`}>
          {score} <span className="text-xs font-normal text-slate-500">/ 100</span>
        </span>
      </div>
    </div>
  )
}

export default function ScanPage() {
  const [url, setUrl] = useState('')
  const [scanning, setScanning] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [currentDomain, setCurrentDomain] = useState('')
  
  const reportRef = useRef(null)
  const abortControllerRef = useRef(null)

  // Clean up any pending scan on unmount
  useEffect(() => {
    return () => {
      if (abortControllerRef.current) {
        abortControllerRef.current.abort()
      }
    }
  }, [])

  const handleScan = useCallback(async (e) => {
    e?.preventDefault()
    const targetUrl = url.trim()
    if (!targetUrl) return

    // Cancel any previous in-flight scan immediately
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }
    abortControllerRef.current = new AbortController()

    let parsedDomain = ''
    try {
      parsedDomain = targetUrl.replace(/^https?:\/\//, '').split('/')[0].split(':')[0]
    } catch (_) {
      parsedDomain = targetUrl
    }

    setCurrentDomain(parsedDomain)
    setScanning(true)
    setError(null)

    try {
      const res = await scanUrl(targetUrl, {
        signal: abortControllerRef.current.signal
      })

      let finalData = res.data

      // If backend didn't include IP intel, fetch as non-blocking fallback
      if (!finalData.ipIntel && finalData.domain) {
        try {
          const ipData = await getIPIntelligence(finalData.domain)
          finalData = { ...finalData, ipIntel: ipData }
        } catch (ipErr) {
          console.warn('IP Intelligence fallback fetch warning:', ipErr.message)
        }
      }

      setResult(finalData)
      setError(null)
    } catch (err) {
      // Ignore user-initiated abort cancellations
      if (err.name === 'CanceledError' || err.code === 'ERR_CANCELED') {
        return
      }
      setError(err.message || 'Scan failed. Please check the URL and try again.')
    } finally {
      setScanning(false)
    }
  }, [url])

  const downloadReport = async () => {
    if (!reportRef.current || !result) return
    const btn = document.getElementById('dl-btn')
    if (btn) btn.style.display = 'none'

    try {
      const canvas = await html2canvas(reportRef.current, {
        scale: 2,
        backgroundColor: '#080C14',
        logging: false
      })
      const imgData = canvas.toDataURL('image/png')
      const pdf = new jsPDF('p', 'mm', 'a4')
      const pdfWidth = pdf.internal.pageSize.getWidth()
      const pdfHeight = (canvas.height * pdfWidth) / canvas.width

      pdf.addImage(imgData, 'PNG', 0, 0, pdfWidth, pdfHeight)
      pdf.save(`${result.domain}-security-report.pdf`)
    } catch (e) {
      console.error('PDF generation failed', e)
    } finally {
      if (btn) btn.style.display = 'flex'
    }
  }

  const riskBadgeClass = useMemo(() => {
    const r = result?.riskLevel?.toLowerCase() || ''
    if (r === 'malicious' || r === 'high risk' || (result?.threatScore > 50)) return 'badge-critical'
    if (r === 'suspicious' || (result?.threatScore > 20)) return 'badge-suspicious'
    return 'badge-safe'
  }, [result])

  return (
    <div className="space-y-5 animate-fade-in relative z-10 max-w-6xl mx-auto">
      {/* Page Header */}
      <div className="flex justify-between items-center pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white uppercase font-sans">
            URL Threat Scanner
          </h2>
          <p className="text-slate-400 font-mono text-xs mt-0.5">
            Real-time multi-engine threat reconnaissance and heuristic analysis
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-800 text-[11px] font-mono text-slate-400">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            PARALLEL ENGINES ONLINE
          </span>
        </div>
      </div>

      {/* Input Search Box */}
      <div className="soc-card p-4 bg-slate-900/60 border border-slate-800">
        <form onSubmit={handleScan} className="flex gap-3">
          <div className="relative flex-1">
            <input
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter URL to inspect (e.g. https://example.com/login)"
              className="input-soc font-mono text-sm pl-4 pr-10"
              disabled={scanning}
            />
            {url && !scanning && (
              <button
                type="button"
                onClick={() => setUrl('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 text-xs font-mono"
              >
                ✕
              </button>
            )}
          </div>
          <button
            type="submit"
            className="btn-primary min-w-[170px]"
            disabled={scanning || !url.trim()}
          >
            {scanning ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                <span>SCANNING...</span>
              </>
            ) : (
              <>
                <span>⌕</span>
                <span>ANALYZE URL</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Scan Progress Monitor */}
      {scanning && (
        <ScanProgress
          isScanning={scanning}
          domain={currentDomain}
          statuses={result?.engineStatuses}
        />
      )}

      {/* Error Message */}
      {error && !scanning && (
        <div className="bg-red-950/40 border border-red-800/80 text-red-300 px-4 py-3 rounded text-xs font-mono flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-red-400 font-bold">[ SCAN ERROR ]</span>
            <span>{error}</span>
          </div>
          <button
            onClick={() => setError(null)}
            className="text-slate-400 hover:text-white ml-4"
          >
            ✕
          </button>
        </div>
      )}

      {/* Security Report View */}
      {result && (
        <div ref={reportRef} className="soc-card p-5 border border-slate-800 bg-slate-950/90 space-y-5">
          
          {/* =========================================================================
              PRIORITY 1: THREAT VERDICT & OVERVIEW (Displayed FIRST at the top)
              ========================================================================= */}
          <div className="p-4 rounded border border-slate-800 bg-slate-900/80 flex flex-wrap items-center justify-between gap-4">
            <div className="flex items-center gap-6">
              {/* Threat Gauge */}
              <ThreatScoreBadge
                score={result.threatScore || 0}
                riskLevel={result.riskLevel}
              />

              <div className="h-10 w-px bg-slate-800 hidden sm:block"></div>

              {/* Classification & Probability */}
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-slate-500 uppercase">Verdict:</span>
                  <span className={`badge ${riskBadgeClass}`}>
                    {result.riskLevel}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[10px] font-mono text-slate-500 uppercase">Phishing Risk:</span>
                  <span className="text-xs font-mono font-semibold text-slate-200 uppercase">
                    {result.phishingProbability || 'UNKNOWN'}
                  </span>
                </div>
              </div>
            </div>

            {/* Target Metadata & Actions */}
            <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3">
              <div className="text-left sm:text-right font-mono text-xs">
                <div className="text-slate-300 font-semibold truncate max-w-[280px]" title={result.domain}>
                  {result.domain}
                </div>
                <div className="text-slate-500 text-[10px]">
                  {result.createdAt ? new Date(result.createdAt).toUTCString() : new Date().toUTCString()}
                </div>
              </div>

              <button
                id="dl-btn"
                onClick={downloadReport}
                className="btn-primary bg-slate-800 hover:bg-slate-700 text-slate-200 border-slate-700 py-1.5 px-3 text-xs"
              >
                <span>↓</span>
                <span>EXPORT PDF</span>
              </button>
            </div>
          </div>

          {/* =========================================================================
              EVIDENCE & INTELLIGENCE PANELS (Compact 2-Column SOC Grid)
              ========================================================================= */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

            {/* Panel 1: Threat Signatures & Heuristics */}
            <div className="soc-card p-4 border-slate-800/80 bg-slate-900/40">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
                <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                  Threat Signatures & Anomalies
                </h4>
                <span className="text-[10px] font-mono text-slate-500">
                  {result.issues?.length || 0} DETECTIONS
                </span>
              </div>

              {result.issues && result.issues.length > 0 ? (
                <ul className="space-y-2">
                  {result.issues.map((issue, idx) => (
                    <li key={idx} className="flex items-start gap-2 text-xs font-mono">
                      <span className="text-red-400 mt-0.5">✕</span>
                      <span className="text-slate-300">{issue}</span>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="flex items-center gap-2 py-3 text-xs font-mono text-emerald-400">
                  <span>✓</span>
                  <span>No malicious threat signatures matched</span>
                </div>
              )}
            </div>

            {/* Panel 2: Intelligence Engines (Google Safe Browsing, VirusTotal, Piracy) */}
            <div className="soc-card p-4 border-slate-800/80 bg-slate-900/40">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
                <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                  Reputation Engines & Blacklists
                </h4>
                <span className="text-[10px] font-mono text-slate-500">MULTI-SOURCE</span>
              </div>

              <div className="space-y-2.5 font-mono text-xs">
                {/* VirusTotal */}
                <div className="flex items-center justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">VirusTotal Detection</span>
                  <div>
                    {result.virusTotal?.status === 'TIMEOUT' ? (
                      <span className="text-amber-400 text-[11px]">[ TIMEOUT ]</span>
                    ) : result.virusTotal?.status === 'UNAVAILABLE' ? (
                      <span className="text-slate-500 text-[11px]">[ UNAVAILABLE ]</span>
                    ) : (
                      <span className={result.virusTotal?.malicious > 0 ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                        {result.virusTotal?.malicious > 0
                          ? `${result.virusTotal.malicious} / ${result.virusTotal.totalEngines || 0} ENGINES FLAGGED`
                          : `CLEAN (0 / ${result.virusTotal?.totalEngines || 0} ENGINES)`}
                      </span>
                    )}
                  </div>
                </div>

                {/* Google Safe Browsing */}
                <div className="flex items-center justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Google Safe Browsing</span>
                  <div>
                    {result.googleSafeBrowsing?.status === 'TIMEOUT' ? (
                      <span className="text-amber-400 text-[11px]">[ TIMEOUT ]</span>
                    ) : result.googleSafeBrowsing?.status === 'UNAVAILABLE' ? (
                      <span className="text-slate-500 text-[11px]">[ NOT CONFIGURED ]</span>
                    ) : result.googleSafeBrowsing?.isSafe ? (
                      <span className="text-emerald-400">[ CLEAN / UNLISTED ]</span>
                    ) : (
                      <span className="text-red-400 font-bold">
                        [ FLAGGED: {result.googleSafeBrowsing?.threats?.join(', ') || 'MALWARE'} ]
                      </span>
                    )}
                  </div>
                </div>

                {/* Piracy Indicator */}
                <div className="flex items-center justify-between py-1 border-b border-slate-800/60">
                  <span className="text-slate-400">Piracy / Copyright Vector</span>
                  <span className={
                    result.piracyStatus === 'High Piracy Risk' ? 'text-red-400 font-bold' :
                    result.piracyStatus === 'Possible Piracy' ? 'text-amber-400' : 'text-emerald-400'
                  }>
                    {result.piracyStatus || 'No Piracy Signals'}
                  </span>
                </div>

                {/* SSL/TLS Security */}
                <div className="flex items-center justify-between py-1">
                  <span className="text-slate-400">SSL / TLS Protocol</span>
                  <span className={result.sslStatus?.valid ? 'text-emerald-400' : 'text-red-400'}>
                    {result.sslStatus?.status || (result.sslStatus?.valid ? 'VALID' : 'INSECURE')}
                    {result.sslStatus?.daysRemaining > 0 && ` (${result.sslStatus.daysRemaining} days left)`}
                  </span>
                </div>
              </div>
            </div>

            {/* Panel 3: Domain Reconnaissance */}
            <div className="soc-card p-4 border-slate-800/80 bg-slate-900/40">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
                <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                  Domain Reconnaissance
                </h4>
                <span className="text-[10px] font-mono text-slate-500">WHOIS / DNS</span>
              </div>

              <div className="grid grid-cols-2 gap-x-4 gap-y-2.5 font-mono text-xs">
                <div>
                  <span className="block text-[10px] text-slate-500 uppercase">Registrar</span>
                  <span className="text-slate-200 truncate block" title={result.domainInfo?.registrar}>
                    {result.domainInfo?.registrar || 'UNKNOWN'}
                  </span>
                </div>
                <div>
                  <span className="block text-[10px] text-slate-500 uppercase">Domain Age</span>
                  <span className="text-slate-200">
                    {result.domainInfo?.age != null
                      ? `${result.domainInfo.age} days (~${(result.domainInfo.age / 365).toFixed(1)} yrs)`
                      : 'UNKNOWN'}
                  </span>
                </div>
                <div>
                  <span className="block text-[10px] text-slate-500 uppercase">Registrant Country</span>
                  <span className="text-slate-200">
                    {result.domainInfo?.country || 'UNKNOWN'}
                  </span>
                </div>
                <div>
                  <span className="block text-[10px] text-slate-500 uppercase">Registered Date</span>
                  <span className="text-slate-200 truncate block">
                    {result.domainInfo?.creationDate
                      ? new Date(result.domainInfo.creationDate).toISOString().split('T')[0]
                      : 'UNKNOWN'}
                  </span>
                </div>
                <div className="col-span-2">
                  <span className="block text-[10px] text-slate-500 uppercase">Nameservers</span>
                  <span className="text-slate-300 text-[11px] truncate block">
                    {result.domainInfo?.nameservers?.length > 0
                      ? result.domainInfo.nameservers.join(', ')
                      : 'None detected'}
                  </span>
                </div>
              </div>
            </div>

            {/* Panel 4: Network & Geolocation (IP Intelligence) */}
            <div className="soc-card p-4 border-slate-800/80 bg-slate-900/40">
              <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
                <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                  Network & Geolocation
                </h4>
                <span className="text-[10px] font-mono text-slate-500">IP INTEL</span>
              </div>

              {result.ipIntel ? (
                <div className="grid grid-cols-2 gap-x-4 gap-y-2.5 font-mono text-xs">
                  <div>
                    <span className="block text-[10px] text-slate-500 uppercase">IP Address</span>
                    <span className="text-sky-400 font-bold">{result.ipIntel.ip}</span>
                  </div>
                  <div>
                    <span className="block text-[10px] text-slate-500 uppercase">Location</span>
                    <div className="flex items-center gap-1.5 text-slate-200">
                      {result.ipIntel.country && (
                        <img
                          src={`https://flagcdn.com/w20/${result.ipIntel.country.toLowerCase()}.png`}
                          alt={result.ipIntel.country}
                          className="w-3.5 h-2.5 opacity-90 inline-block"
                          onError={(e) => e.target.style.display = 'none'}
                        />
                      )}
                      <span className="truncate">
                        {[result.ipIntel.city, result.ipIntel.country].filter(Boolean).join(', ') || 'Unknown'}
                      </span>
                    </div>
                  </div>
                  <div>
                    <span className="block text-[10px] text-slate-500 uppercase">Autonomous System (ASN)</span>
                    <span className="text-slate-200 bg-slate-800 px-1.5 py-0.5 rounded text-[11px] border border-slate-700">
                      {result.ipIntel.asn || 'Unknown'}
                    </span>
                  </div>
                  <div>
                    <span className="block text-[10px] text-slate-500 uppercase">ISP / Organization</span>
                    <span className="text-slate-300 truncate block" title={result.ipIntel.org}>
                      {result.ipIntel.org || result.domainInfo?.hostingProvider || 'Unknown'}
                    </span>
                  </div>
                </div>
              ) : (
                <div className="text-xs font-mono text-slate-500 py-3">
                  IP Intelligence data unavailable for this host.
                </div>
              )}
            </div>

          </div>

          {/* Engine Status Audit Footnote */}
          {result.engineStatuses && (
            <div className="pt-3 border-t border-slate-800/60 flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-500">
              <div className="flex items-center gap-4">
                <span>Engines Queried: 8</span>
                <span>•</span>
                <span>Mode: Parallel Concurrent</span>
                <span>•</span>
                <span>Cache: {result.isCached ? 'ACTIVE HIT' : 'POPULATED'}</span>
              </div>
              <div className="text-slate-500">
                PhishGuard Enterprise AI Threat Protection
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  )
}
