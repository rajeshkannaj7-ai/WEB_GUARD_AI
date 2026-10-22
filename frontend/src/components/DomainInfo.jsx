import { useState } from 'react'
import { getDomainInfo, getIPIntelligence } from '../services/api'

const ReconRow = ({ label, value, highlight }) => (
  <div className="flex items-center justify-between py-1.5 border-b border-slate-800/60 font-mono text-xs">
    <span className="text-slate-400 text-[11px] uppercase">{label}</span>
    <span className={`font-semibold ${highlight ? 'text-sky-400' : 'text-slate-200'} truncate max-w-[280px]`}>
      {value || 'Unknown / Obfuscated'}
    </span>
  </div>
)

export default function DomainInfo() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [ipIntel, setIpIntel] = useState(null)
  const [error, setError] = useState(null)

  const handleLookup = async (e) => {
    e.preventDefault()
    const cleanDomain = domain.trim().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]
    if (!cleanDomain) return

    setLoading(true)
    setResult(null)
    setIpIntel(null)
    setError(null)

    try {
      const [res, ipRes] = await Promise.all([
        getDomainInfo(cleanDomain),
        getIPIntelligence(cleanDomain).catch(err => {
          console.warn('IP Intel lookup error:', err.message)
          return null
        })
      ])
      setResult(res.data)
      setIpIntel(ipRes)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-5 animate-fade-in relative z-10 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex justify-between items-center pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white uppercase font-sans">
            Domain Reconnaissance
          </h2>
          <p className="text-slate-400 font-mono text-xs mt-0.5">
            Extract WHOIS, DNS routing, and IP intelligence on target hosts
          </p>
        </div>
      </div>

      {/* Input Box */}
      <div className="soc-card p-4 bg-slate-900/60 border border-slate-800">
        <form onSubmit={handleLookup} className="flex gap-3">
          <input
            type="text"
            value={domain}
            onChange={e => setDomain(e.target.value)}
            placeholder="Enter domain name (e.g. google.com or paypal.com)"
            className="input-soc font-mono text-sm flex-1"
            disabled={loading}
          />
          <button
            type="submit"
            className="btn-primary min-w-[170px]"
            disabled={loading || !domain.trim()}
          >
            {loading ? (
              <>
                <span className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin"></span>
                <span>EXTRACTING...</span>
              </>
            ) : (
              <>
                <span>⌘</span>
                <span>INITIATE RECON</span>
              </>
            )}
          </button>
        </form>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-950/40 border border-red-800/80 text-red-300 px-4 py-3 rounded text-xs font-mono">
          [ RECON ERROR ] {error}
        </div>
      )}

      {/* Results Grid */}
      {result && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 animate-slide-up">
          
          {/* Card 1: WHOIS Registration Intelligence */}
          <div className="soc-card p-4 border border-slate-800 bg-slate-900/40">
            <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
              <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                WHOIS Registration Intelligence
              </h4>
              <span className="text-sky-400 font-mono text-[10px] bg-sky-950/60 border border-sky-800/60 px-1.5 py-0.5 rounded">
                WHOIS-XML
              </span>
            </div>

            <div className="space-y-1">
              <ReconRow label="Target Domain" value={result.domain} highlight />
              <ReconRow label="Registrar Name" value={result.registrar} />
              <ReconRow label="Registrant Country" value={result.country} />
              <ReconRow 
                label="Domain Age" 
                value={result.domainAge != null ? `${result.domainAge} days (~${(result.domainAge / 365).toFixed(1)} yrs)` : 'Unknown'} 
              />
              <ReconRow 
                label="Creation Date" 
                value={result.creationDate ? new Date(result.creationDate).toISOString().split('T')[0] : 'Unknown'} 
              />
              <ReconRow 
                label="Expiration Date" 
                value={result.expirationDate ? new Date(result.expirationDate).toISOString().split('T')[0] : 'Unknown'} 
              />
              <ReconRow 
                label="Hosting Provider" 
                value={result.hostingProvider} 
              />
            </div>
          </div>

          {/* Card 2: IP Intelligence & Geolocation */}
          <div className="soc-card p-4 border border-slate-800 bg-slate-900/40">
            <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
              <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                IP Geolocation & Routing
              </h4>
              <span className="text-emerald-400 font-mono text-[10px] bg-emerald-950/60 border border-emerald-800/60 px-1.5 py-0.5 rounded">
                IP-INTEL
              </span>
            </div>

            {ipIntel ? (
              <div className="space-y-1">
                <ReconRow label="Resolved IP" value={ipIntel.ip} highlight />
                <div className="flex items-center justify-between py-1.5 border-b border-slate-800/60 font-mono text-xs">
                  <span className="text-slate-400 text-[11px] uppercase">Country</span>
                  <div className="flex items-center gap-1.5 text-slate-200">
                    {ipIntel.country && (
                      <img 
                        src={`https://flagcdn.com/w20/${ipIntel.country.toLowerCase()}.png`} 
                        alt={ipIntel.country}
                        className="w-3.5 h-2.5 opacity-90 inline-block"
                        onError={(e) => e.target.style.display = 'none'}
                      />
                    )}
                    <span>{ipIntel.country}</span>
                  </div>
                </div>
                <ReconRow label="City / Region" value={[ipIntel.city, ipIntel.region].filter(Boolean).join(', ')} />
                <ReconRow label="ISP Organization" value={ipIntel.org} />
                <ReconRow label="Autonomous System (ASN)" value={ipIntel.asn} />
              </div>
            ) : (
              <div className="py-6 text-center text-slate-500 font-mono text-xs">
                IP intelligence query not resolved for this host.
              </div>
            )}
          </div>

          {/* Card 3: Nameservers & DNS */}
          <div className="soc-card p-4 border border-slate-800 bg-slate-900/40">
            <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
              <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                Active Nameservers (DNS)
              </h4>
              <span className="text-slate-500 font-mono text-[10px]">
                {result.nameservers?.length || 0} SERVERS
              </span>
            </div>

            {result.nameservers && result.nameservers.length > 0 ? (
              <ul className="space-y-1.5 font-mono text-xs">
                {result.nameservers.map((ns, idx) => (
                  <li key={idx} className="flex items-center justify-between py-1 border-b border-slate-800/50">
                    <span className="text-slate-500 text-[11px]">NS #{idx + 1}</span>
                    <span className="text-slate-300 font-semibold">{ns}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-slate-500 font-mono text-xs py-4">No nameserver records detected.</div>
            )}
          </div>

          {/* Card 4: SSL/TLS Security Status */}
          <div className="soc-card p-4 border border-slate-800 bg-slate-900/40">
            <div className="flex items-center justify-between pb-2 mb-3 border-b border-slate-800">
              <h4 className="text-xs font-mono font-bold text-slate-300 uppercase tracking-wider">
                SSL / TLS Inspection
              </h4>
              <span className={`font-mono text-[10px] px-1.5 py-0.5 rounded ${
                result.ssl?.valid ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/60' : 'bg-red-950/60 text-red-400 border border-red-800/60'
              }`}>
                {result.ssl?.valid ? 'SECURE' : 'INSECURE'}
              </span>
            </div>

            <div className="space-y-1 font-mono text-xs">
              <ReconRow label="Certificate Status" value={result.ssl?.status} highlight={result.ssl?.valid} />
              <ReconRow 
                label="Days Remaining" 
                value={result.ssl?.daysRemaining != null ? `${result.ssl.daysRemaining} days` : 'N/A'} 
              />
              <ReconRow 
                label="Valid From" 
                value={result.ssl?.validFrom ? new Date(result.ssl.validFrom).toISOString().split('T')[0] : 'Unknown'} 
              />
              <ReconRow 
                label="Valid To" 
                value={result.ssl?.validTo ? new Date(result.ssl.validTo).toISOString().split('T')[0] : 'Unknown'} 
              />
            </div>
          </div>

        </div>
      )}
    </div>
  )
}
