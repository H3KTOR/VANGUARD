import { useMemo, useState } from 'react'
import { Cpu, MemoryStick, HardDrive, Network, ShieldOff, Search, Loader2 } from 'lucide-react'
import { usePolling } from '../hooks/usePolling.js'
import {
  getDashboardSummary,
  getLatestMetric,
  getMetricsHistory,
  listIncidents,
  blockIncidentIP,
  updateIncidentStatus,
} from '../api/vanguardClient.js'
import RiskGauge from './RiskGauge.jsx'
import SystemHealthPanel from './SystemHealthPanel.jsx'
import { ProgressMetricCard, NetworkMetricCard } from './MetricCard.jsx'
import ThreatCounter from './ThreatCounter.jsx'
import AttackDensityChart from './AttackDensityChart.jsx'
import ThreatMixChart from './ThreatMixChart.jsx'
import { SEVERITY_BG, SEVERITY_DOT } from '../utils/severity.js'

function formatUptime(seconds) {
  if (!seconds && seconds !== 0) return '\u2014'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

// Derives a single 0-100 composite "master threat posture" score from the
// dashboard summary: weighted by open-incident severity mix plus a bump
// for active bans, capped at 100. This composite score is a frontend
// presentation concern only (no equivalent field exists on the Go side),
// deliberately conservative so a single LOW incident doesn't spike it.
function computePostureScore(summary) {
  if (!summary) return 0
  const bySev = summary.open_incidents_by_sev || {}
  const weighted =
    (bySev.CRITICAL || 0) * 25 + (bySev.HIGH || 0) * 12 + (bySev.MEDIUM || 0) * 5 + (bySev.LOW || 0) * 1.5
  const banBump = Math.min(summary.active_bans_total || 0, 10) * 1.5
  return Math.max(0, Math.min(100, Math.round(weighted + banBump)))
}

// Buckets the last-24h incident list into 60 one-minute buckets for the
// Attack Density chart (only the most recent 60 minutes are shown).
function buildDensityBuckets(incidents) {
  const now = Date.now()
  const buckets = []
  for (let i = 59; i >= 0; i--) {
    const t = now - i * 60_000
    buckets.push({ t, label: new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }), count: 0 })
  }
  const bucketByMinute = new Map(buckets.map((b, idx) => [Math.floor(b.t / 60000), idx]))
  for (const inc of incidents || []) {
    const ts = new Date(inc.detected_at).getTime()
    const key = Math.floor(ts / 60000)
    const idx = bucketByMinute.get(key)
    if (idx !== undefined) buckets[idx].count += 1
  }
  return buckets
}

function buildNetworkSparkline(history) {
  if (!history?.length) return []
  return history.slice(-12).map((m, i) => ({ i, v: m.active_connections || 0 }))
}

export default function CommandCenter() {
  const [actionBusyId, setActionBusyId] = useState(null)
  const [actionError, setActionError] = useState(null)

  const { data: summary } = usePolling(getDashboardSummary, 5000)
  const { data: latestMetricResp } = usePolling(getLatestMetric, 5000)
  const { data: historyResp } = usePolling(() => getMetricsHistory(1), 15000)
  const { data: recentIncidentsResp, refresh: refreshIncidents } = usePolling(
    () => listIncidents({ since_hours: 1, limit: 500 }),
    5000,
  )
  const { data: openIncidentsResp } = usePolling(
    () => listIncidents({ status: 'open', limit: 10 }),
    6000,
  )

  const metric = latestMetricResp?.metric
  const history = historyResp?.metrics || []
  const postureScore = useMemo(() => computePostureScore(summary), [summary])
  const densityData = useMemo(() => buildDensityBuckets(recentIncidentsResp?.incidents), [recentIncidentsResp])
  const networkSpark = useMemo(() => buildNetworkSparkline(history), [history])
  const bySeverity = summary?.open_incidents_by_sev || {}

  // Trend = today's open count for this severity minus yesterday's proxy
  // (incidents_last_24h total is the closest signal the API exposes
  // without adding a new endpoint); shown as a directional nudge, not a
  // precise delta.
  const trendFor = (sev) => {
    const openCount = bySeverity[sev] || 0
    const proportion = summary?.incidents_last_24h ? openCount / Math.max(1, summary.incidents_last_24h) : 0
    return Math.round(proportion * 3) - 1
  }

  async function handleBlock(incident) {
    setActionBusyId(incident.id)
    setActionError(null)
    try {
      await blockIncidentIP(incident.id, 60)
      await refreshIncidents()
    } catch (e) {
      setActionError(e.message)
    } finally {
      setActionBusyId(null)
    }
  }

  async function handleInvestigate(incident) {
    setActionBusyId(incident.id)
    setActionError(null)
    try {
      await updateIncidentStatus(incident.id, 'investigating')
      await refreshIncidents()
    } catch (e) {
      setActionError(e.message)
    } finally {
      setActionBusyId(null)
    }
  }

  const openIncidents = openIncidentsResp?.incidents || []

  return (
    <div className="p-6 space-y-6 max-w-[1600px] mx-auto">
      {actionError && (
        <div className="rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs px-4 py-2.5">
          {actionError}
        </div>
      )}

      {/* Row 1: Master Threat Posture + System Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 rounded-xl border border-slate-200 bg-white p-5 shadow-card">
          <div className="flex flex-col sm:flex-row items-center gap-6">
            <RiskGauge score={postureScore} />
            <div className="flex-1 w-full">
              <h2 className="text-sm font-bold text-slate-800 mb-1">Master Threat Posture</h2>
              <p className="text-xs text-slate-400 mb-4">
                Composite risk score derived from open incidents, active bans, and severity mix.
              </p>
              <div className="flex flex-wrap gap-2 mb-4">
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-600">
                  {summary?.open_incidents_total ?? 0} open incidents
                </span>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-600">
                  {summary?.active_bans_total ?? 0} active bans
                </span>
                <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold bg-slate-100 text-slate-600">
                  {summary?.tracked_ips ?? 0} IPs tracked
                </span>
                {summary?.panic_mode?.active && (
                  <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-bold bg-red-100 text-red-700">
                    PANIC MODE ACTIVE
                  </span>
                )}
              </div>

              <div className="space-y-2">
                {openIncidents.length === 0 && (
                  <p className="text-xs text-slate-400 italic py-2">No open incidents. All clear.</p>
                )}
                {openIncidents.slice(0, 3).map((inc) => (
                  <div
                    key={inc.id}
                    className="flex items-center justify-between gap-3 rounded-lg border border-slate-100 px-3 py-2 hover:bg-slate-50 transition-colors"
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <span className={`h-2 w-2 rounded-full flex-shrink-0 ${SEVERITY_DOT[inc.severity] || 'bg-slate-400'}`} />
                      <div className="min-w-0">
                        <p className="text-xs font-semibold text-slate-800 truncate">{inc.type?.replace(/_/g, ' ')}</p>
                        <p className="text-[11px] text-slate-400 font-mono truncate">{inc.source_ip}</p>
                      </div>
                      <span
                        className={`hidden sm:inline-flex px-1.5 py-0.5 rounded text-[10px] font-bold ring-1 ring-inset flex-shrink-0 ${
                          SEVERITY_BG[inc.severity] || 'bg-slate-50 text-slate-600 ring-slate-200'
                        }`}
                      >
                        {inc.severity}
                      </span>
                    </div>
                    <div className="flex items-center gap-1.5 flex-shrink-0">
                      <button
                        onClick={() => handleInvestigate(inc)}
                        disabled={actionBusyId === inc.id}
                        className="flex items-center gap-1 rounded-md bg-slate-100 hover:bg-slate-200 text-slate-700 text-[11px] font-semibold px-2 py-1 transition-colors disabled:opacity-50"
                      >
                        <Search className="h-3 w-3" /> Investigate
                      </button>
                      <button
                        onClick={() => handleBlock(inc)}
                        disabled={actionBusyId === inc.id}
                        className="flex items-center gap-1 rounded-md bg-red-600 hover:bg-red-700 text-white text-[11px] font-semibold px-2 py-1 transition-colors disabled:opacity-50"
                      >
                        {actionBusyId === inc.id ? (
                          <Loader2 className="h-3 w-3 animate-spin" />
                        ) : (
                          <ShieldOff className="h-3 w-3" />
                        )}
                        Block
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        <SystemHealthPanel
          agentOnline={!!summary}
          dbHealthy={!!metric}
          honeypotEnabled={true}
          uptimeLabel={formatUptime(metric ? Math.round((Date.now() - new Date(metric.timestamp).getTime()) / -1000) : null)}
        />
      </div>

      {/* Row 2: 4 resource metric cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <ProgressMetricCard icon={Cpu} label="CPU" value={metric?.cpu_percent} sub="Host processor load" />
        <ProgressMetricCard
          icon={MemoryStick}
          label="RAM"
          value={metric?.memory_percent}
          sub={metric ? `${metric.memory_used_mb} MB used` : undefined}
        />
        <ProgressMetricCard icon={HardDrive} label="DISK" value={metric?.disk_percent} sub="Root filesystem" />
        <NetworkMetricCard icon={Network} label="NETWORK I/O" value={metric?.active_connections ?? 0} history={networkSpark} />
      </div>

      {/* Row 3: 4 threat severity counters */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <ThreatCounter severity="CRITICAL" count={bySeverity.CRITICAL || 0} trend={trendFor('CRITICAL')} />
        <ThreatCounter severity="HIGH" count={bySeverity.HIGH || 0} trend={trendFor('HIGH')} />
        <ThreatCounter severity="MEDIUM" count={bySeverity.MEDIUM || 0} trend={trendFor('MEDIUM')} />
        <ThreatCounter severity="LOW" count={bySeverity.LOW || 0} trend={trendFor('LOW')} />
      </div>

      {/* Row 4: Attack Density + Threat Mix */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <AttackDensityChart data={densityData} />
        </div>
        <ThreatMixChart bySeverity={bySeverity} />
      </div>
    </div>
  )
}
