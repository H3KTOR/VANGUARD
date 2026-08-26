import { useState } from 'react'
import { Search, ShieldOff, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { usePolling } from '../hooks/usePolling.js'
import { listIncidents, updateIncidentStatus, blockIncidentIP } from '../api/vanguardClient.js'
import { SEVERITY_BG } from '../utils/severity.js'

const STATUS_LABEL = {
  open: 'Open',
  auto_blocked: 'Auto-Blocked',
  investigating: 'Investigating',
  resolved: 'Resolved',
  false_positive: 'False Positive',
}

export default function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [busyId, setBusyId] = useState(null)
  const [error, setError] = useState(null)

  const { data, refresh, loading } = usePolling(
    () => listIncidents({ status: statusFilter, severity: severityFilter, limit: 200 }),
    6000,
    [statusFilter, severityFilter],
  )
  const incidents = data?.incidents || []

  async function act(fn, id) {
    setBusyId(id)
    setError(null)
    try {
      await fn()
      await refresh()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700"
        >
          <option value="">All statuses</option>
          {Object.entries(STATUS_LABEL).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="rounded-lg border border-slate-300 bg-white px-3 py-2 text-xs font-medium text-slate-700"
        >
          <option value="">All severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        {loading && <Loader2 className="h-4 w-4 animate-spin text-slate-400" />}
      </div>

      {error && <div className="rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs px-4 py-2.5">{error}</div>}

      <div className="rounded-xl border border-slate-200 bg-white shadow-card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50 text-left text-[11px] font-bold uppercase tracking-wide text-slate-500">
              <th className="px-4 py-2.5">Type</th>
              <th className="px-4 py-2.5">Source IP</th>
              <th className="px-4 py-2.5">Severity</th>
              <th className="px-4 py-2.5">Risk</th>
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5">Detected</th>
              <th className="px-4 py-2.5 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {incidents.map((inc) => (
              <tr key={inc.id} className="hover:bg-slate-50/60">
                <td className="px-4 py-2.5 font-medium text-slate-800 capitalize">{inc.type?.replace(/_/g, ' ')}</td>
                <td className="px-4 py-2.5 font-mono text-xs text-slate-600">{inc.source_ip}</td>
                <td className="px-4 py-2.5">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ring-1 ring-inset ${SEVERITY_BG[inc.severity] || ''}`}>
                    {inc.severity}
                  </span>
                </td>
                <td className="px-4 py-2.5 tabular-nums text-slate-600">{inc.risk_score}</td>
                <td className="px-4 py-2.5 text-slate-600">{STATUS_LABEL[inc.status] || inc.status}</td>
                <td className="px-4 py-2.5 text-slate-400 text-xs">{new Date(inc.detected_at).toLocaleString()}</td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center justify-end gap-1.5">
                    <button
                      title="Investigate"
                      disabled={busyId === inc.id}
                      onClick={() => act(() => updateIncidentStatus(inc.id, 'investigating'), inc.id)}
                      className="h-7 w-7 flex items-center justify-center rounded-md bg-slate-100 hover:bg-slate-200 text-slate-600"
                    >
                      <Search className="h-3.5 w-3.5" />
                    </button>
                    <button
                      title="Block IP"
                      disabled={busyId === inc.id}
                      onClick={() => act(() => blockIncidentIP(inc.id, 60), inc.id)}
                      className="h-7 w-7 flex items-center justify-center rounded-md bg-red-50 hover:bg-red-100 text-red-600"
                    >
                      <ShieldOff className="h-3.5 w-3.5" />
                    </button>
                    <button
                      title="Resolve"
                      disabled={busyId === inc.id}
                      onClick={() => act(() => updateIncidentStatus(inc.id, 'resolved'), inc.id)}
                      className="h-7 w-7 flex items-center justify-center rounded-md bg-green-50 hover:bg-green-100 text-green-600"
                    >
                      <CheckCircle2 className="h-3.5 w-3.5" />
                    </button>
                    <button
                      title="Mark False Positive"
                      disabled={busyId === inc.id}
                      onClick={() => act(() => updateIncidentStatus(inc.id, 'false_positive'), inc.id)}
                      className="h-7 w-7 flex items-center justify-center rounded-md bg-slate-100 hover:bg-slate-200 text-slate-500"
                    >
                      <XCircle className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </td>
              </tr>
            ))}
            {incidents.length === 0 && !loading && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-sm text-slate-400">
                  No incidents match the current filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
