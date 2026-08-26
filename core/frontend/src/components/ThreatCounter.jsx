import { TrendingUp, TrendingDown, Minus } from 'lucide-react'

const STYLES = {
  CRITICAL: { text: 'text-red-600', bg: 'bg-red-50', ring: 'ring-red-100', dot: 'bg-red-600' },
  HIGH: { text: 'text-orange-600', bg: 'bg-orange-50', ring: 'ring-orange-100', dot: 'bg-orange-500' },
  MEDIUM: { text: 'text-amber-600', bg: 'bg-amber-50', ring: 'ring-amber-100', dot: 'bg-amber-500' },
  LOW: { text: 'text-green-600', bg: 'bg-green-50', ring: 'ring-green-100', dot: 'bg-green-600' },
}

// ThreatCounter: one of the four "Active Threats by Severity" tiles,
// each showing the current open-incident count for that severity and a
// trend indicator (vs. the same count 24h ago) sourced from the
// dashboard summary's `incidents_last_24h` comparison in CommandCenter.
export default function ThreatCounter({ severity, count, trend }) {
  const s = STYLES[severity] || STYLES.LOW
  const TrendIcon = trend > 0 ? TrendingUp : trend < 0 ? TrendingDown : Minus
  const trendColor = trend > 0 ? 'text-red-500' : trend < 0 ? 'text-green-500' : 'text-slate-400'

  return (
    <div className={`rounded-xl border border-slate-200 bg-white p-4 shadow-card ring-1 ring-inset ${s.ring}`}>
      <div className="flex items-center gap-1.5 mb-2">
        <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
        <span className="text-[11px] font-bold tracking-wide text-slate-500 uppercase">{severity}</span>
      </div>
      <div className={`text-3xl font-extrabold tabular-nums ${s.text}`}>{count}</div>
      <div className={`flex items-center gap-1 mt-1.5 text-[11px] font-semibold ${trendColor}`}>
        <TrendIcon className="h-3 w-3" />
        <span>
          {trend === 0 ? 'No change' : `${Math.abs(trend)} ${trend > 0 ? 'more' : 'fewer'}`} vs 24h ago
        </span>
      </div>
    </div>
  )
}
