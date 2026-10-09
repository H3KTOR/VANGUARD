import { useEffect, useState } from 'react'
import { getIncidentEvents, getResponsePlan } from '../api/vanguardClient.js'
import { KIND_LABEL, parseMetadata, planLabel, provenanceOf, responseSummary } from '../utils/evidence.js'

const STATE_STYLE = {
  verified: 'bg-green-50 text-green-700 ring-green-200',
  unverified: 'bg-amber-50 text-amber-700 ring-amber-200',
  inconclusive: 'bg-amber-50 text-amber-700 ring-amber-200',
  verification_failed: 'bg-red-50 text-red-700 ring-red-200',
  failed: 'bg-red-50 text-red-700 ring-red-200',
  none: 'bg-slate-100 text-slate-600 ring-slate-200',
}

// Evidence panel for one incident: provenance (observed vs inferred),
// the response/verification status, the planned (not executed) action,
// the audit timeline and the raw structured evidence.
export default function IncidentEvidence({ incident }) {
  const [events, setEvents] = useState(null)
  const [plan, setPlan] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    setEvents(null)
    setPlan(null)
    setError(null)
    getIncidentEvents(incident.id)
      .then((r) => alive && setEvents(r.events || []))
      .catch((e) => alive && setError(e.message))
    getResponsePlan(incident.id)
      .then((p) => alive && setPlan(p))
      .catch(() => {}) // plan is optional context
    return () => {
      alive = false
    }
  }, [incident.id])

  const meta = parseMetadata(incident.metadata)
  const prov = provenanceOf(meta)
  const summary = responseSummary(events)

  return (
    <div className="space-y-3 text-xs text-slate-700">
      <div>
        <div className="font-bold uppercase tracking-wide text-[10px] text-slate-500">Provenance</div>
        {prov ? (
          <div>
            <span className="font-mono">{prov.ruleId}</span> r{prov.revision} — {KIND_LABEL[prov.kind]}
            {prov.limitations && <div className="text-slate-500">Limits: {prov.limitations}</div>}
          </div>
        ) : (
          <div className="text-slate-500">No provenance recorded (incident predates Phase 5).</div>
        )}
      </div>

      <div>
        <div className="font-bold uppercase tracking-wide text-[10px] text-slate-500">Response</div>
        {events === null && !error ? (
          <span className="text-slate-400">Loading…</span>
        ) : (
          <span className={`inline-block px-2 py-0.5 rounded ring-1 ring-inset ${STATE_STYLE[summary.state] || STATE_STYLE.none}`}>
            {summary.label}
          </span>
        )}
        {plan && <div className="mt-1 text-slate-500">{planLabel(plan)}</div>}
      </div>

      <div>
        <div className="font-bold uppercase tracking-wide text-[10px] text-slate-500">Timeline</div>
        {error && <div className="text-red-600">Could not load history: {error}</div>}
        {events && events.length === 0 && <div className="text-slate-500">No lifecycle or response events recorded.</div>}
        {events && events.length > 0 && (
          <ul className="space-y-0.5">
            {events.map((e) => (
              <li key={e.id}>
                <span className="text-slate-400">{new Date(e.at).toLocaleString()}</span>{' '}
                <span className="font-semibold">{e.kind.replace('_', ' ')}</span>
                {e.from_status && e.to_status && (
                  <span>
                    {' '}
                    {e.from_status} → {e.to_status}
                  </span>
                )}
                {e.outcome && <span> [{e.outcome}]</span>}
                {e.actor && <span className="text-slate-400"> by {e.actor}</span>}
                {e.detail && <span className="text-slate-500"> — {e.detail}</span>}
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <div className="font-bold uppercase tracking-wide text-[10px] text-slate-500">Structured evidence</div>
        <pre className="max-h-72 overflow-auto rounded-lg bg-slate-900 p-3 text-[11px] leading-relaxed text-slate-100">
          {meta ? JSON.stringify(meta, null, 2) : incident.metadata || 'No structured evidence recorded.'}
        </pre>
      </div>
    </div>
  )
}
