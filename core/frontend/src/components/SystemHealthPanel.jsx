import { Database, Radio, Cpu, Clock, CheckCircle2, XCircle } from 'lucide-react'

function Row({ icon: Icon, label, status, detail }) {
  const ok = status === true
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-slate-100 last:border-0">
      <div className="flex items-center gap-2.5">
        <div className="h-7 w-7 rounded-lg bg-slate-100 flex items-center justify-center flex-shrink-0">
          <Icon className="h-3.5 w-3.5 text-slate-500" />
        </div>
        <span className="text-xs font-semibold text-slate-700">{label}</span>
      </div>
      <div className="flex items-center gap-1.5">
        {detail && <span className="text-[11px] text-slate-400 tabular-nums">{detail}</span>}
        {ok ? (
          <CheckCircle2 className="h-4 w-4 text-green-500" />
        ) : (
          <XCircle className="h-4 w-4 text-red-500" />
        )}
      </div>
    </div>
  )
}

// SystemHealthPanel: the small at-a-glance checklist confirming every
// core subsystem wired up in cmd/vanguard/serve.go is actually alive --
// Agent (HTTP health endpoint reachable), SQLite (a metric write landed
// recently), Honeypot (decoys configured/reachable), plus daemon Uptime.
export default function SystemHealthPanel({ agentOnline, dbHealthy, honeypotEnabled, uptimeLabel }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 shadow-card">
      <h3 className="text-xs font-bold text-slate-500 uppercase tracking-wide mb-1">System Health</h3>
      <div>
        <Row icon={Cpu} label="Agent" status={agentOnline} />
        <Row icon={Database} label="SQLite Database" status={dbHealthy} />
        <Row icon={Radio} label="Honeypot Listeners" status={honeypotEnabled} />
        <Row icon={Clock} label="Daemon Uptime" status={true} detail={uptimeLabel} />
      </div>
    </div>
  )
}
