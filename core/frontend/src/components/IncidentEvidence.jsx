import { useEffect, useState, useCallback } from 'react'
import {
  getIncidentEvents,
  getResponsePlan,
  getIncidentTimeline,
  getIncidentGraph,
  listNotes,
  addNote,
  deleteNote,
  exportIncident,
} from '../api/vanguardClient.js'
import {
  KIND_LABEL,
  PROVENANCE_LABEL,
  PROVENANCE_STYLE,
  downloadName,
  parseMetadata,
  planLabel,
  provenanceOf,
  relationText,
  responseSummary,
  timelineNotice,
} from '../utils/evidence.js'

const STATE_STYLE = {
  verified: 'bg-green-50 text-green-700 ring-green-200',
  unverified: 'bg-amber-50 text-amber-700 ring-amber-200',
  inconclusive: 'bg-amber-50 text-amber-700 ring-amber-200',
  verification_failed: 'bg-red-50 text-red-700 ring-red-200',
  failed: 'bg-red-50 text-red-700 ring-red-200',
  none: 'bg-slate-100 text-slate-600 ring-slate-200',
}

const H = ({ children }) => <div className="font-bold uppercase tracking-wide text-[10px] text-slate-500">{children}</div>

// Investigation panel for one incident: provenance, response status, the
// unified timeline (each entry labelled observed / derived / correlated /
// analyst / response), explicit data gaps, explicit-reference relationships,
// analyst notes (kept apart from detector evidence), a redacted export, and
// the raw structured evidence. Everything shown comes from stored records;
// an empty section means "nothing persisted", never "nothing happened".
export default function IncidentEvidence({ incident }) {
  const [events, setEvents] = useState(null)
  const [plan, setPlan] = useState(null)
  const [timeline, setTimeline] = useState(null)
  const [graph, setGraph] = useState(null)
  const [notes, setNotes] = useState(null)
  const [draft, setDraft] = useState('')
  const [error, setError] = useState(null)
  const [noteError, setNoteError] = useState(null)
  const [exportError, setExportError] = useState(null)

  const loadNotes = useCallback(
    () =>
      listNotes(incident.id)
        .then((r) => setNotes(r.notes || []))
        .catch((e) => setNoteError(e.message)),
    [incident.id],
  )

  useEffect(() => {
    let alive = true
    setEvents(null)
    setPlan(null)
    setTimeline(null)
    setGraph(null)
    setNotes(null)
    setError(null)
    getIncidentEvents(incident.id)
      .then((r) => alive && setEvents(r.events || []))
      .catch((e) => alive && setError(e.message))
    getResponsePlan(incident.id)
      .then((p) => alive && setPlan(p))
      .catch(() => {}) // plan is optional context
    getIncidentTimeline(incident.id)
      .then((t) => alive && setTimeline(t))
      .catch((e) => alive && setError(e.message))
    getIncidentGraph(incident.id)
      .then((g) => alive && setGraph(g))
      .catch(() => {})
    loadNotes()
    return () => {
      alive = false
    }
  }, [incident.id, loadNotes])

  async function submitNote() {
    setNoteError(null)
    try {
      await addNote(incident.id, draft)
      setDraft('')
      await loadNotes()
    } catch (e) {
      setNoteError(e.message)
    }
  }

  async function removeNote(id) {
    setNoteError(null)
    try {
      await deleteNote(incident.id, id)
      await loadNotes()
    } catch (e) {
      setNoteError(e.message)
    }
  }

  async function doExport() {
    setExportError(null)
    try {
      const text = await exportIncident(incident.id)
      const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }))
      const a = document.createElement('a')
      a.href = url
      a.download = downloadName(incident.id)
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setExportError(e.message)
    }
  }

  const meta = parseMetadata(incident.metadata)
  const prov = provenanceOf(meta)
  const summary = responseSummary(events)
  const notice = timelineNotice(timeline)
  const otherIncidents = (graph?.edges || []).filter((e) => e.relation === 'shares_indicator')

  return (
    <div className="space-y-3 text-xs text-slate-700">
      <div>
        <H>Provenance</H>
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
        <H>Response</H>
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
        <H>Timeline</H>
        {error && <div className="text-red-600">Could not load history: {error}</div>}
        {timeline === null && !error && <span className="text-slate-400">Loading…</span>}
        {notice && <div className="text-slate-500">{notice}</div>}
        {timeline && timeline.entries.length > 0 && (
          <ul className="space-y-0.5">
            {timeline.entries.map((e) => (
              <li key={e.ref}>
                <span className="text-slate-400">{new Date(e.at).toLocaleString()}</span>{' '}
                <span className={`px-1 rounded ring-1 ring-inset ${PROVENANCE_STYLE[e.provenance] || ''}`}>
                  {PROVENANCE_LABEL[e.provenance] || e.provenance}
                </span>{' '}
                <span>{e.summary}</span>
              </li>
            ))}
          </ul>
        )}
        {timeline && timeline.total > timeline.entries.length && (
          <div className="text-slate-500">Showing {timeline.entries.length} of {timeline.total} entries.</div>
        )}
        {timeline && timeline.data_gaps?.length > 0 && (
          <details className="mt-1">
            <summary className="cursor-pointer text-amber-700">What this timeline cannot tell you ({timeline.data_gaps.length})</summary>
            <ul className="list-disc ml-4 text-slate-600">
              {timeline.data_gaps.map((g) => <li key={g}>{g}</li>)}
            </ul>
          </details>
        )}
      </div>

      <div>
        <H>Related incidents (explicit references only)</H>
        {otherIncidents.length === 0 ? (
          <div className="text-slate-500">No other retained incident shares an indicator with this one. Closeness in time or address is not used to link incidents.</div>
        ) : (
          <ul className="list-disc ml-4">
            {otherIncidents.map((e) => <li key={e.ref}>{relationText(e)}</li>)}
          </ul>
        )}
      </div>

      <div>
        <H>Analyst notes (human statements, not detector evidence)</H>
        {noteError && <div className="text-red-600">{noteError}</div>}
        {notes && notes.length === 0 && <div className="text-slate-500">No notes.</div>}
        {notes && notes.length > 0 && (
          <ul className="space-y-1">
            {notes.map((n) => (
              <li key={n.id} className="rounded bg-white border border-slate-200 p-1.5">
                <div className="text-slate-400">{n.author} · {new Date(n.created_at).toLocaleString()}{n.edited_at ? ' (edited)' : ''}</div>
                {/* rendered as text, never as HTML */}
                <div className="whitespace-pre-wrap">{n.text}</div>
                <button className="underline text-slate-500" onClick={() => removeNote(n.id)}>Delete</button>
              </li>
            ))}
          </ul>
        )}
        <div className="mt-1 flex gap-1">
          <input value={draft} onChange={(e) => setDraft(e.target.value)} maxLength={2000} placeholder="Add a note (max 2000 chars)" className="flex-1 rounded border border-slate-300 px-2 py-1" />
          <button disabled={!draft.trim()} onClick={submitNote} className="rounded bg-slate-900 text-white px-2 py-1 disabled:opacity-50">Add note</button>
        </div>
      </div>

      <div>
        <button onClick={doExport} className="underline">Export investigation (JSON, secrets masked)</button>
        <span className="text-slate-500"> — not signed or tamper-evident.</span>
        {exportError && <div className="text-red-600">{exportError}</div>}
      </div>

      <div>
        <H>Structured evidence</H>
        <pre className="max-h-72 overflow-auto rounded-lg bg-slate-900 p-3 text-[11px] leading-relaxed text-slate-100">
          {meta ? JSON.stringify(meta, null, 2) : incident.metadata || 'No structured evidence recorded.'}
        </pre>
      </div>
    </div>
  )
}
