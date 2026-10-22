import { useEffect, useState, useCallback, useMemo } from 'react'
import { Line, Doughnut } from 'react-chartjs-2'
import {
  Chart as ChartJS, CategoryScale, LinearScale, PointElement,
  LineElement, Title, Tooltip, Legend, ArcElement, Filler
} from 'chart.js'
import { getDashboard } from '../services/api'
import ReportTable from './ReportTable'

ChartJS.register(
  CategoryScale, LinearScale, PointElement, LineElement,
  Title, Tooltip, Legend, ArcElement, Filler
)

const MetricCard = ({ title, value, subtitle, icon, borderColor, textColor, badgeText, badgeColor }) => (
  <div className={`soc-card p-4 bg-slate-900/60 border ${borderColor || 'border-slate-800'} relative flex flex-col justify-between`}>
    <div className="flex justify-between items-start mb-2">
      <span className="text-slate-400 text-[11px] font-mono uppercase tracking-wider">
        {title}
      </span>
      {badgeText && (
        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold ${badgeColor || 'bg-slate-800 text-slate-400'}`}>
          {badgeText}
        </span>
      )}
    </div>
    <div className="flex items-baseline justify-between">
      <div>
        <p className={`text-2xl font-mono font-bold ${textColor || 'text-white'}`}>
          {value ?? '—'}
        </p>
        {subtitle && (
          <p className="text-slate-500 text-[11px] mt-1 font-mono">
            {subtitle}
          </p>
        )}
      </div>
      <div className="text-lg opacity-40 text-slate-400 font-mono">
        {icon}
      </div>
    </div>
  </div>
)

export default function Dashboard() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const loadDashboard = useCallback(async () => {
    try {
      const res = await getDashboard()
      setData(res.data)
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    loadDashboard()
    const interval = setInterval(loadDashboard, 30000)
    return () => clearInterval(interval)
  }, [loadDashboard])

  const lineChartData = useMemo(() => ({
    labels: data?.chartData?.labels || [],
    datasets: [
      {
        label: 'Total Scans',
        data: data?.chartData?.scans || [],
        borderColor: '#0EA5E9',
        backgroundColor: 'rgba(14, 165, 233, 0.08)',
        borderWidth: 2,
        tension: 0.25,
        fill: true,
        pointBackgroundColor: '#0EA5E9',
        pointBorderColor: '#080C14',
        pointBorderWidth: 1.5,
        pointRadius: 3,
        pointHoverRadius: 5,
      },
      {
        label: 'Malicious',
        data: data?.chartData?.highRisk || [],
        borderColor: '#EF4444',
        backgroundColor: 'rgba(239, 68, 68, 0.08)',
        borderWidth: 2,
        tension: 0.25,
        fill: true,
        pointBackgroundColor: '#EF4444',
        pointBorderColor: '#080C14',
        pointBorderWidth: 1.5,
        pointRadius: 3,
        pointHoverRadius: 5,
      }
    ]
  }), [data])

  const doughnutData = useMemo(() => ({
    labels: ['Safe', 'Suspicious', 'Malicious'],
    datasets: [
      {
        data: [
          data?.threatDistribution?.['SAFE'] || 0,
          data?.threatDistribution?.['SUSPICIOUS'] || 0,
          data?.threatDistribution?.['MALICIOUS'] || 0,
        ],
        backgroundColor: [
          'rgba(16, 185, 129, 0.85)',
          'rgba(245, 158, 11, 0.85)',
          'rgba(239, 68, 68, 0.85)'
        ],
        borderColor: ['#10B981', '#F59E0B', '#EF4444'],
        borderWidth: 1,
        hoverOffset: 3
      }
    ]
  }), [data])

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: '#94A3B8',
          font: { family: 'JetBrains Mono', size: 11 },
          boxWidth: 10,
          usePointStyle: true
        }
      },
      tooltip: {
        backgroundColor: '#0F172A',
        titleColor: '#F8FAFC',
        bodyColor: '#E2E8F0',
        borderColor: '#334155',
        borderWidth: 1,
        titleFont: { family: 'JetBrains Mono', size: 11 },
        bodyFont: { family: 'JetBrains Mono', size: 11 },
        padding: 8,
        cornerRadius: 4
      }
    },
    scales: {
      x: {
        grid: { color: 'rgba(30, 41, 59, 0.4)' },
        ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 10 } }
      },
      y: {
        grid: { color: 'rgba(30, 41, 59, 0.4)' },
        ticks: { color: '#64748B', font: { family: 'JetBrains Mono', size: 10 }, stepSize: 1 }
      }
    }
  }

  const doughnutOptions = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: '72%',
    plugins: {
      legend: {
        position: 'bottom',
        labels: {
          color: '#94A3B8',
          font: { family: 'JetBrains Mono', size: 10 },
          usePointStyle: true,
          padding: 12
        }
      },
      tooltip: {
        backgroundColor: '#0F172A',
        titleColor: '#F8FAFC',
        bodyColor: '#E2E8F0',
        borderColor: '#334155',
        borderWidth: 1,
        titleFont: { family: 'JetBrains Mono' },
        bodyFont: { family: 'JetBrains Mono' }
      }
    }
  }

  if (loading && !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[400px] gap-3 text-sky-400 font-mono">
        <div className="w-5 h-5 border-2 border-sky-400 border-t-transparent rounded-full animate-spin"></div>
        <p className="text-xs uppercase tracking-wider text-slate-400">Loading Threat Telemetry...</p>
      </div>
    )
  }

  const safePercent = (data?.safeDomains && data.totalScans)
    ? Math.round((data.safeDomains / data.totalScans) * 100)
    : 0

  return (
    <div className="space-y-5 animate-fade-in relative z-10 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex justify-between items-center pb-2 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white uppercase font-sans">
            SOC Intelligence Overview
          </h2>
          <p className="text-slate-400 font-mono text-xs mt-0.5">
            Aggregated threat detections, heuristic vectors, and telemetry
          </p>
        </div>
        <button
          onClick={loadDashboard}
          className="text-sky-400 border border-sky-500/30 bg-sky-500/10 hover:bg-sky-500/20 px-3 py-1.5 rounded text-xs font-mono transition-colors flex items-center gap-1.5"
        >
          <span>↻</span>
          <span>REFRESH</span>
        </button>
      </div>

      {error && (
        <div className="bg-red-950/40 border border-red-800/80 text-red-300 px-4 py-2.5 rounded text-xs font-mono">
          [TELEMETRY ERROR] {error}
        </div>
      )}

      {/* 4 Compact Telemetry Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
        <MetricCard
          title="TOTAL SCANS"
          value={data?.totalScans?.toLocaleString()}
          subtitle={`${data?.scansToday || 0} scans logged today`}
          icon="⌘"
          textColor="text-sky-400"
          borderColor="border-slate-800"
          badgeText="ALL TIME"
          badgeColor="bg-slate-800 text-slate-400"
        />
        <MetricCard
          title="MALICIOUS BLOCKED"
          value={data?.highRiskDetected?.toLocaleString()}
          subtitle="Confirmed malicious threat"
          icon="✕"
          textColor="text-red-400"
          borderColor="border-red-900/40"
          badgeText="ACTION TAKEN"
          badgeColor="bg-red-950/80 text-red-400"
        />
        <MetricCard
          title="SUSPICIOUS DOMAINS"
          value={data?.suspiciousDomains?.toLocaleString()}
          subtitle="Heuristic anomalies flagged"
          icon="⚠"
          textColor="text-amber-400"
          borderColor="border-amber-900/40"
          badgeText="WATCHLIST"
          badgeColor="bg-amber-950/80 text-amber-400"
        />
        <MetricCard
          title="SAFE TRAFFIC"
          value={data?.safeDomains?.toLocaleString()}
          subtitle={`${safePercent}% verified clean`}
          icon="✓"
          textColor="text-emerald-400"
          borderColor="border-emerald-900/40"
          badgeText="CLEAN"
          badgeColor="bg-emerald-950/80 text-emerald-400"
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Activity Volume Line Chart */}
        <div className="lg:col-span-2 soc-card p-4 bg-slate-900/50 border border-slate-800">
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-slate-300 font-sans font-semibold text-xs uppercase tracking-wider">
              Scan Activity & Detection Volume
            </h3>
            <span className="text-slate-500 font-mono text-[10px]">7-DAY TIMELINE</span>
          </div>
          <div className="h-56">
            <Line data={lineChartData} options={chartOptions} />
          </div>
        </div>

        {/* Threat Distribution Doughnut Chart */}
        <div className="soc-card p-4 bg-slate-900/50 border border-slate-800">
          <div className="flex justify-between items-center mb-3">
            <h3 className="text-slate-300 font-sans font-semibold text-xs uppercase tracking-wider">
              Threat Breakdown
            </h3>
            <span className="text-slate-500 font-mono text-[10px]">GLOBAL RATIO</span>
          </div>
          <div className="h-56 flex justify-center items-center relative">
            {data?.totalScans > 0 ? (
              <Doughnut data={doughnutData} options={doughnutOptions} />
            ) : (
              <span className="text-slate-500 font-mono text-xs">NO SCANS RECORDED</span>
            )}
          </div>
        </div>
      </div>

      {/* Recent Detections Table Feed */}
      <div className="soc-card overflow-hidden border border-slate-800 bg-slate-900/50">
        <div className="px-4 py-3 border-b border-slate-800 bg-slate-950/60 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <h3 className="text-slate-300 font-sans font-semibold text-xs uppercase tracking-wider">
              Recent Threat Detections Feed
            </h3>
            <span className="text-emerald-400 font-mono text-[10px] bg-emerald-950/60 border border-emerald-800/60 px-1.5 py-0.5 rounded">
              LIVE
            </span>
          </div>
          <span className="text-slate-500 font-mono text-[10px]">
            Latest {data?.recentScans?.length || 0} entries
          </span>
        </div>
        <ReportTable scans={data?.recentScans || []} />
      </div>
    </div>
  )
}
