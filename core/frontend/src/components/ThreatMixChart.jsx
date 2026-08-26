import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import { SEVERITY_COLORS, SEVERITY_ORDER } from '../utils/severity.js'

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const p = payload[0]
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-3 py-2 shadow-lg text-xs">
      <p className="font-semibold" style={{ color: p.payload.fill }}>
        {p.name}
      </p>
      <p className="text-slate-500">
        <span className="font-bold text-slate-900">{p.value}</span> incidents
      </p>
    </div>
  )
}

function Legend({ data, total }) {
  return (
    <div className="flex flex-col gap-2 justify-center">
      {SEVERITY_ORDER.map((sev) => {
        const item = data.find((d) => d.name === sev)
        const value = item?.value ?? 0
        const pct = total > 0 ? Math.round((value / total) * 100) : 0
        return (
          <div key={sev} className="flex items-center gap-2 text-xs">
            <span className="h-2.5 w-2.5 rounded-sm flex-shrink-0" style={{ backgroundColor: SEVERITY_COLORS[sev] }} />
            <span className="text-slate-600 font-medium w-16">{sev}</span>
            <span className="font-bold text-slate-900 tabular-nums">{value}</span>
            <span className="text-slate-400">({pct}%)</span>
          </div>
        )
      })}
    </div>
  )
}

// ThreatMixChart: donut chart breaking down currently-open incidents by
// severity, paired with a manual legend (Recharts' built-in Legend
// doesn't give us the tight value+percentage layout the mockup wants).
export default function ThreatMixChart({ bySeverity = {} }) {
  const data = SEVERITY_ORDER.map((sev) => ({ name: sev, value: bySeverity[sev] || 0 })).filter((d) => d.value > 0)
  const total = Object.values(bySeverity).reduce((a, b) => a + b, 0)
  const displayData = data.length ? data : [{ name: 'LOW', value: 1 }]

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-card h-full">
      <div className="mb-3">
        <h3 className="text-sm font-bold text-slate-800">Threat Mix</h3>
        <p className="text-[11px] text-slate-400">Open incidents by severity</p>
      </div>
      <div className="flex items-center gap-4">
        <div className="h-40 w-40 flex-shrink-0 relative">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={displayData}
                dataKey="value"
                nameKey="name"
                innerRadius={48}
                outerRadius={68}
                paddingAngle={total > 0 ? 3 : 0}
                strokeWidth={0}
                isAnimationActive={false}
              >
                {displayData.map((entry) => (
                  <Cell
                    key={entry.name}
                    fill={total > 0 ? SEVERITY_COLORS[entry.name] : '#e2e8f0'}
                  />
                ))}
              </Pie>
              {total > 0 && <Tooltip content={<CustomTooltip />} />}
            </PieChart>
          </ResponsiveContainer>
          <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
            <span className="text-2xl font-extrabold text-slate-900">{total}</span>
            <span className="text-[10px] text-slate-400 font-semibold">TOTAL</span>
          </div>
        </div>
        <Legend data={data} total={total} />
      </div>
    </div>
  )
}
