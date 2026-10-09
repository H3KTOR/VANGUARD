import { useState } from 'react'
import { Loader2, Upload, Search } from 'lucide-react'
import { usePolling } from '../hooks/usePolling.js'
import {
  getIntelStatus,
  listIOCs,
  setIOCEnabled,
  importIOCs,
  listIOCImports,
  huntMatches,
} from '../api/vanguardClient.js'
import { STATE_STYLE, indicatorWarnings, explainMatch, importSummary, buildHuntQuery } from '../utils/intel.js'

function StatusBar() {
  const { data } = usePolling(() => getIntelStatus(), 15000, [])
  if (!data) return null
  const m = data.matcher
  return (
    <div className="rounded-lg border border-slate-200 bg-white px-4 py-2 text-xs text-slate-700 flex flex-wrap gap-x-6 gap-y-1">
      <span>Indicators: <b>{data.indicators_total}</b> ({data.indicators_active} active)</span>
      {data.enabled === false ? (
        <span className="text-amber-700">Matching disabled (-intel=false)</span>
      ) : m && !m.loaded ? (
        <span className="text-red-700">Matcher has not loaded — no matching is happening{m.last_error ? `: ${m.last_error}` : ''}</span>
      ) : m ? (
        <>
          <span>Snapshot: {m.indicators_loaded} loaded{m.loaded_at ? ` at ${new Date(m.loaded_at).toLocaleTimeString()}` : ''}</span>
          {m.truncated && <span className="text-amber-700">Snapshot truncated — more active indicators exist than are loaded</span>}
          {m.last_error && <span className="text-red-700">Last reload failed (previous snapshot kept): {m.last_error}</span>}
        </>
      ) : null}
      {data.last_import && (
        <span className={data.last_import.status === 'rejected' ? 'text-red-700' : ''}>
          Last import: {data.last_import.status} ({data.last_import.source || 'n/a'})
        </span>
      )}
    </div>
  )
}

function Indicators() {
  const [type, setType] = useState('')
  const [state, setState] = useState('')
  const [err, setErr] = useState(null)
  const [open, setOpen] = useState(null)
  const { data, refresh, loading } = usePolling(() => listIOCs({ type, state, limit: 200 }), 15000, [type, state])
  const rows = data?.indicators || []

  async function toggle(r) {
    setErr(null)
    try {
      await setIOCEnabled(r.id, r.state === 'disabled')
      await refresh()
    } catch (e) {
      setErr(e.message)
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex gap-2 items-center">
        <select value={type} onChange={(e) => setType(e.target.value)} className="rounded border border-slate-300 bg-white px-2 py-1 text-xs">
          <option value="">All types</option>
          {['ip', 'domain', 'url', 'sha256'].map((t) => <option key={t}>{t}</option>)}
        </select>
        <select value={state} onChange={(e) => setState(e.target.value)} className="rounded border border-slate-300 bg-white px-2 py-1 text-xs">
          <option value="">Any state</option>
          <option value="active">Active only</option>
          <option value="disabled">Disabled only</option>
        </select>
        {loading && <Loader2 className="h-4 w-4 animate-spin text-slate-400" />}
      </div>
      {err && <div className="rounded bg-red-50 border border-red-200 text-red-700 text-xs px-3 py-2">{err}</div>}
      <div className="rounded-xl border border-slate-200 bg-white overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-slate-50 text-left text-[10px] font-bold uppercase text-slate-500">
              <th className="px-3 py-2">State</th><th className="px-3 py-2">Type</th><th className="px-3 py-2">Value</th>
              <th className="px-3 py-2">Source</th><th className="px-3 py-2">Confidence</th><th className="px-3 py-2">Expires</th><th className="px-3 py-2" />
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rows.map((r) => (
              <>
                <tr key={r.id} className="hover:bg-slate-50 cursor-pointer" onClick={() => setOpen(open === r.id ? null : r.id)}>
                  <td className="px-3 py-2"><span className={`px-1.5 py-0.5 rounded ring-1 ring-inset ${STATE_STYLE[r.state]}`}>{r.state}</span></td>
                  <td className="px-3 py-2">{r.type}</td>
                  <td className="px-3 py-2 font-mono break-all">{r.value}</td>
                  <td className="px-3 py-2">{r.source}</td>
                  <td className="px-3 py-2">{r.confidence || 'unrated'}</td>
                  <td className="px-3 py-2">{r.expires_at ? new Date(r.expires_at).toLocaleDateString() : 'none supplied'}</td>
                  <td className="px-3 py-2">
                    <button className="underline" onClick={(e) => { e.stopPropagation(); toggle(r) }}>
                      {r.state === 'disabled' ? 'Enable' : 'Disable'}
                    </button>
                  </td>
                </tr>
                {open === r.id && (
                  <tr key={`${r.id}-d`} className="bg-slate-50">
                    <td colSpan={7} className="px-3 py-2 space-y-1">
                      {r.description && <div>{r.description}</div>}
                      {r.reference && <div className="text-slate-500">Reference (not fetched): {r.reference}</div>}
                      <ul className="list-disc ml-4 text-slate-600">
                        {indicatorWarnings(r).map((w) => <li key={w}>{w}</li>)}
                      </ul>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {rows.length === 0 && !loading && (
              <tr><td colSpan={7} className="px-3 py-8 text-center text-slate-400">No indicators match. Import a feed to begin.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function ImportPanel() {
  const [text, setText] = useState('')
  const [strict, setStrict] = useState(false)
  const [busy, setBusy] = useState(false)
  const [report, setReport] = useState(null)
  const [err, setErr] = useState(null)
  const { data: hist, refresh } = usePolling(() => listIOCImports(10), 20000, [])

  async function run() {
    setBusy(true)
    setErr(null)
    setReport(null)
    try {
      setReport(await importIOCs(text, { strict }))
      await refresh()
    } catch (e) {
      setErr(e.message)
      if (e.body) setReport(e.body)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-500">
        Paste a <code>vanguard-ioc</code> v1 JSON/JSONL feed (max 10 MiB / 50 000 records). Import is local and offline; feed content is stored as inert data.
      </p>
      <textarea value={text} onChange={(e) => setText(e.target.value)} rows={8} className="w-full rounded border border-slate-300 p-2 font-mono text-xs" placeholder='{"format":"vanguard-ioc","version":1,"source":"my-feed","indicators":[...]}' />
      <label className="text-xs flex items-center gap-2"><input type="checkbox" checked={strict} onChange={(e) => setStrict(e.target.checked)} /> Strict (any invalid record rejects the whole import)</label>
      <button disabled={busy || !text.trim()} onClick={run} className="inline-flex items-center gap-2 rounded bg-slate-900 text-white px-3 py-1.5 text-xs disabled:opacity-50">
        {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Upload className="h-3.5 w-3.5" />} Import
      </button>
      {err && !report && <div className="rounded bg-red-50 border border-red-200 text-red-700 text-xs px-3 py-2">{err}</div>}
      {report && (
        <div className={`rounded border text-xs px-3 py-2 ${report.status === 'rejected' ? 'bg-red-50 border-red-200 text-red-800' : 'bg-green-50 border-green-200 text-green-800'}`}>
          <div>{importSummary(report)}</div>
          {report.reject_sample?.length > 0 && (
            <ul className="mt-1 list-disc ml-4">{report.reject_sample.map((s) => <li key={s}>{s}</li>)}</ul>
          )}
        </div>
      )}
      <div>
        <div className="text-[10px] font-bold uppercase tracking-wide text-slate-500 mb-1">Recent imports</div>
        <ul className="text-xs space-y-0.5">
          {(hist?.imports || []).map((i) => (
            <li key={i.id} className={i.status === 'rejected' ? 'text-red-700' : ''}>
              {new Date(i.created_at).toLocaleString()} — {i.source || 'n/a'} — {i.status}
              {i.status === 'applied' ? ` (+${i.accepted} / ~${i.updated} / ${i.rejected} invalid)` : `: ${i.error}`}
            </li>
          ))}
          {(hist?.imports || []).length === 0 && <li className="text-slate-400">No imports yet.</li>}
        </ul>
      </div>
    </div>
  )
}

function Hunt() {
  const [f, setF] = useState({ ioc_type: '', kind: '', ip: '', context: '', since_hours: '24', limit: '50' })
  const [rows, setRows] = useState(null)
  const [err, setErr] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (k) => (e) => setF({ ...f, [k]: e.target.value })

  async function run() {
    setBusy(true)
    setErr(null)
    try {
      const r = await huntMatches(buildHuntQuery(f))
      setRows(r.matches || [])
    } catch (e) {
      setErr(e.message)
      setRows(null)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 md:grid-cols-6 gap-2 text-xs">
        <select value={f.ioc_type} onChange={set('ioc_type')} className="rounded border border-slate-300 bg-white px-2 py-1">
          <option value="">Any type</option>{['ip', 'domain', 'url', 'sha256'].map((t) => <option key={t}>{t}</option>)}
        </select>
        <select value={f.kind} onChange={set('kind')} className="rounded border border-slate-300 bg-white px-2 py-1">
          <option value="">Direct + context</option><option value="direct">Direct matches</option><option value="enrichment">Context only</option>
        </select>
        <input value={f.ip} onChange={set('ip')} placeholder="source IP" className="rounded border border-slate-300 px-2 py-1" />
        <input value={f.context} onChange={set('context')} placeholder="exact matched value" className="rounded border border-slate-300 px-2 py-1" />
        <input value={f.since_hours} onChange={set('since_hours')} placeholder="last N hours" className="rounded border border-slate-300 px-2 py-1" />
        <button onClick={run} disabled={busy} className="inline-flex items-center justify-center gap-1 rounded bg-slate-900 text-white px-2 py-1 disabled:opacity-50">
          {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />} Hunt
        </button>
      </div>
      <p className="text-[11px] text-slate-500">Searches recorded indicator matches only (bounded history, newest first, max 200 per page). VANGUARD does not retain raw events, so absence of a result is not proof that a value was never seen.</p>
      {err && <div className="rounded bg-red-50 border border-red-200 text-red-700 text-xs px-3 py-2">{err}</div>}
      {rows && rows.length === 0 && <div className="text-xs text-slate-500">No recorded matches for these filters.</div>}
      {rows && rows.length > 0 && (
        <ul className="space-y-2">
          {rows.map((m) => (
            <li key={m.id} className="rounded border border-slate-200 bg-white p-2 text-xs">
              <div className="font-mono">{new Date(m.matched_at).toLocaleString()} — {m.ioc_type} <b>{m.context}</b> ← {m.source_ip}</div>
              <div className="text-slate-600">{explainMatch(m)}</div>
              {m.incident_id ? <div className="text-slate-500">Incident #{m.incident_id} ({m.incident_type}, {m.incident_status})</div> : null}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

const TABS = [['indicators', 'Indicators'], ['import', 'Import'], ['hunt', 'Hunt']]

// IntelPage: local threat-intelligence workflows (indicators, import,
// bounded hunting). Everything is offline; nothing here performs a lookup.
export default function IntelPage() {
  const [tab, setTab] = useState('indicators')
  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-4">
      <StatusBar />
      <div className="flex gap-1 border-b border-slate-200">
        {TABS.map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)} className={`px-3 py-1.5 text-xs font-semibold border-b-2 ${tab === id ? 'border-slate-900 text-slate-900' : 'border-transparent text-slate-500'}`}>
            {label}
          </button>
        ))}
      </div>
      {tab === 'indicators' && <Indicators />}
      {tab === 'import' && <ImportPanel />}
      {tab === 'hunt' && <Hunt />}
    </div>
  )
}
