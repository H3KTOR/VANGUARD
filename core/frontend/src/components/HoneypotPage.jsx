import { Radio } from 'lucide-react'
import { usePolling } from '../hooks/usePolling.js'
import { listIncidents } from '../api/vanguardClient.js'
import { SEVERITY_BG } from '../utils/severity.js'

// HoneypotPage surfaces incidents specifically of type honeypot_trigger --
// the Go API has no dedicated /api/honeypot endpoint, so this reuses the
// generic incidents list filtered by type, which is exactly how
// serve.go's engine.IngestHoneypotHit records every decoy connection.
export default function HoneypotPage() {
  const { data, loading } = usePolling(() => listIncidents({ type: 'honeypot_trigger', limit: 200 }), 6000)
  const hits = data?.incidents || []

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-4">
      <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-card flex items-center gap-3">
        <div className="h-10 w-10 rounded-lg bg-brand-50 flex items-center justify-center">
          <Radio className="h-5 w-5 text-brand-600" />
        </div>
        <div>
          <p className="text-sm font-bold text-slate-800">Decoy Listeners</p>
          <p className="text-xs text-slate-400">
            Fake SSH (2222), MySQL (33060) and admin panel (8081) services -- any connection is an
            unambiguous attack signal and is auto-escalated to CRITICAL.
          </p>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white shadow-card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50 text-left text-[11px] font-bold uppercase tracking-wide text-slate-500">
              <th className="px-4 py-2.5">Source IP</th>
              <th className="px-4 py-2.5">Severity</th>
              <th className="px-4 py-2.5">Risk Score</th>
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5">Triggered At</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {hits.map((h) => (
              <tr key={h.id} className="hover:bg-slate-50/60">
                <td className="px-4 py-2.5 font-mono text-xs text-slate-800">{h.source_ip}</td>
                <td className="px-4 py-2.5">
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ring-1 ring-inset ${SEVERITY_BG[h.severity] || ''}`}>
                    {h.severity}
                  </span>
                </td>
                <td className="px-4 py-2.5 tabular-nums text-slate-600">{h.risk_score}</td>
                <td className="px-4 py-2.5 text-slate-600">{h.status}</td>
                <td className="px-4 py-2.5 text-slate-400 text-xs">{new Date(h.detected_at).toLocaleString()}</td>
              </tr>
            ))}
            {hits.length === 0 && !loading && (
              <tr>
                <td colSpan={5} className="px-4 py-10 text-center text-sm text-slate-400">
                  No honeypot triggers recorded yet.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
