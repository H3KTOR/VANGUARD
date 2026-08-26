import { AreaChart, Area, ResponsiveContainer } from 'recharts'

// MetricCard renders one of the four top-row resource tiles.
// - CPU / RAM / DISK: icon + value + a horizontal progress bar that
//   changes color as it approaches capacity (green -> amber -> red).
// - NETWORK I/O: no percentage makes sense, so it renders a compact
//   sparkline of recent throughput samples instead of a progress bar.
function barColor(pct) {
  if (pct >= 90) return '#dc2626'
  if (pct >= 75) return '#ea580c'
  if (pct >= 50) return '#d97706'
  return '#16a34a'
}

export function ProgressMetricCard({ icon: Icon, label, value, unit = '%', sub }) {
  const pct = Math.max(0, Math.min(100, value ?? 0))
  const color = barColor(pct)
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-card">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="h-8 w-8 rounded-lg bg-slate-100 flex items-center justify-center">
            <Icon className="h-4 w-4 text-slate-600" strokeWidth={2} />
          </div>
          <span className="text-xs font-semibold text-slate-500">{label}</span>
        </div>
      </div>
      <div className="flex items-end gap-1 mb-2">
        <span className="text-2xl font-extrabold text-slate-900 tabular-nums">{pct.toFixed(0)}</span>
        <span className="text-sm font-semibold text-slate-400 mb-0.5">{unit}</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-slate-100 overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      {sub && <p className="text-[11px] text-slate-400 mt-1.5">{sub}</p>}
    </div>
  )
}

export function NetworkMetricCard({ icon: Icon, label, value, history = [] }) {
  const chartData = history.length ? history : Array.from({ length: 12 }, (_, i) => ({ i, v: 0 }))
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-card">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="h-8 w-8 rounded-lg bg-slate-100 flex items-center justify-center">
            <Icon className="h-4 w-4 text-slate-600" strokeWidth={2} />
          </div>
          <span className="text-xs font-semibold text-slate-500">{label}</span>
        </div>
      </div>
      <div className="flex items-end gap-1 mb-1">
        <span className="text-2xl font-extrabold text-slate-900 tabular-nums">{value}</span>
        <span className="text-sm font-semibold text-slate-400 mb-0.5">conn</span>
      </div>
      <div className="h-8 -mx-1">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={chartData} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="netSpark" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#4f46e5" stopOpacity={0.35} />
                <stop offset="100%" stopColor="#4f46e5" stopOpacity={0} />
              </linearGradient>
            </defs>
            <Area type="monotone" dataKey="v" stroke="#4f46e5" strokeWidth={1.75} fill="url(#netSpark)" isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      <p className="text-[11px] text-slate-400 mt-1">Active connections, last 12 samples</p>
    </div>
  )
}
