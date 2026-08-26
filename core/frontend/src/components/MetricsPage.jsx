import { useState } from 'react'
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { usePolling } from '../hooks/usePolling.js'
import { getMetricsHistory } from '../api/vanguardClient.js'

const RANGES = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '24h', hours: 24 },
  { label: '7d', hours: 168 },
]

export default function MetricsPage() {
  const [hours, setHours] = useState(1)
  const { data, loading } = usePolling(() => getMetricsHistory(hours), 10000, [hours])
  const metrics = (data?.metrics || []).map((m) => ({
    ...m,
    label: new Date(m.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  }))

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-4">
      <div className="flex items-center gap-2">
        {RANGES.map((r) => (
          <button
            key={r.hours}
            onClick={() => setHours(r.hours)}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-colors ${
              hours === r.hours ? 'bg-slate-900 text-white' : 'bg-white border border-slate-200 text-slate-600 hover:bg-slate-50'
            }`}
          >
            {r.label}
          </button>
        ))}
        {loading && <span className="text-xs text-slate-400">Loading...</span>}
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-card">
        <h3 className="text-sm font-bold text-slate-800 mb-3">CPU / Memory / Disk (%)</h3>
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={metrics} margin={{ top: 4, right: 16, left: -16, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={32} />
              <Tooltip />
              <Legend wrapperStyle={{ fontSize: 11 }} />
              <Line type="monotone" dataKey="cpu_percent" name="CPU" stroke="#4f46e5" strokeWidth={2} dot={false} isAnimationActive={false} />
              <Line type="monotone" dataKey="memory_percent" name="RAM" stroke="#0891b2" strokeWidth={2} dot={false} isAnimationActive={false} />
              <Line type="monotone" dataKey="disk_percent" name="Disk" stroke="#d97706" strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-card">
        <h3 className="text-sm font-bold text-slate-800 mb-3">Active Connections</h3>
        <div className="h-56">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={metrics} margin={{ top: 4, right: 16, left: -16, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" vertical={false} />
              <XAxis dataKey="label" tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize: 10, fill: '#94a3b8' }} tickLine={false} width={32} allowDecimals={false} />
              <Tooltip />
              <Line type="monotone" dataKey="active_connections" name="Connections" stroke="#16a34a" strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}
