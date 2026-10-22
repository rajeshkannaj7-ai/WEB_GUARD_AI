import { Link, useLocation } from 'react-router-dom'

const navLinks = [
  { path: '/', label: 'Overview', icon: '◱' },
  { path: '/scan', label: 'URL Scanner', icon: '⌕' },
  { path: '/domain', label: 'Domain Intel', icon: '⌘' },
]

export default function Navbar() {
  const location = useLocation()

  return (
    <aside className="fixed left-0 top-0 h-full w-56 bg-slate-950 border-r border-slate-800/80 z-50 flex flex-col">
      {/* Enterprise Brand */}
      <div className="h-16 flex items-center px-4 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded bg-slate-900 border border-sky-500/40 flex items-center justify-center">
            <span className="text-sky-400 font-mono font-bold text-xs">PG</span>
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <h1 className="text-white font-bold tracking-tight text-sm font-sans uppercase">
                PhishGuard
              </h1>
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
            </div>
            <span className="text-slate-500 text-[9px] font-mono tracking-wider uppercase block">
              SOC Threat Engine
            </span>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-5 px-3 space-y-1">
        <p className="px-2.5 text-[10px] font-mono text-slate-500 uppercase tracking-wider mb-2">
          Security Modules
        </p>
        {navLinks.map(link => {
          const isActive = location.pathname === link.path
          return (
            <Link
              key={link.path}
              to={link.path}
              className={`flex items-center gap-2.5 px-2.5 py-2 rounded text-xs font-medium transition-colors ${
                isActive 
                  ? 'text-white bg-slate-900 border border-slate-700/80 font-semibold' 
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/50'
              }`}
            >
              <span className={`text-base font-mono ${isActive ? 'text-sky-400' : 'text-slate-500'}`}>
                {link.icon}
              </span>
              <span>{link.label}</span>
              {isActive && (
                <span className="ml-auto w-1 h-3.5 rounded bg-sky-400"></span>
              )}
            </Link>
          )
        })}
      </nav>

      {/* System Telemetry Status */}
      <div className="p-3.5 border-t border-slate-800/80 bg-slate-950">
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] font-mono text-slate-400 font-bold uppercase tracking-wider">
            SYSTEM STATUS
          </span>
          <span className="flex h-1.5 w-1.5 relative">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500"></span>
          </span>
        </div>
        <div className="space-y-1 font-mono text-[10px]">
          <div className="flex justify-between">
            <span className="text-slate-500">API Gateway</span>
            <span className="text-emerald-400 font-semibold">ONLINE</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">Threat Engines</span>
            <span className="text-emerald-400 font-semibold">ACTIVE (8)</span>
          </div>
          <div className="flex justify-between">
            <span className="text-slate-500">TTL Cache</span>
            <span className="text-sky-400 font-semibold">READY</span>
          </div>
        </div>
      </div>
    </aside>
  )
}
