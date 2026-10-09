import { useCallback, useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import {
  listRules,
  getTuning,
  previewTuning,
  applyTuning,
  rollbackTuning,
  getRuleGuidance,
} from '../api/vanguardClient.js'
import { autoResponseText, canApply, changeText, enabledText, errorMessage, isAdmin, patchFrom } from '../utils/rules.js'

function Inventory() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [open, setOpen] = useState(null)
  useEffect(() => {
    listRules().then(setData).catch((e) => setError(e.message))
  }, [])
  if (error) return <div className="text-xs text-red-600">{error}</div>
  if (!data) return <Loader2 className="h-4 w-4 animate-spin text-slate-400" />
  return (
    <div className="space-y-2">
      <ul className="text-[11px] text-slate-500 list-disc ml-4">{(data.notes || []).map((n) => <li key={n}>{n}</li>)}</ul>
      <div className="rounded-xl border border-slate-200 bg-white overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-slate-50 text-left text-[10px] font-bold uppercase text-slate-500">
              <th className="px-3 py-2">Rule</th><th className="px-3 py-2">Category</th><th className="px-3 py-2">State</th>
              <th className="px-3 py-2">Base</th><th className="px-3 py-2">Evidence</th><th className="px-3 py-2">Auto-response</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {data.rules.map((r) => (
              <>
                <tr key={r.rule_id} className="hover:bg-slate-50 cursor-pointer" onClick={() => setOpen(open === r.rule_id ? null : r.rule_id)}>
                  <td className="px-3 py-2 font-mono">{r.rule_id}</td>
                  <td className="px-3 py-2">{r.category}</td>
                  <td className="px-3 py-2">{enabledText(r)}</td>
                  <td className="px-3 py-2">{r.base_severity}</td>
                  <td className="px-3 py-2">{r.evidence_kind}</td>
                  <td className="px-3 py-2">{autoResponseText(r.automated_response)}</td>
                </tr>
                {open === r.rule_id && (
                  <tr key={`${r.rule_id}-d`} className="bg-slate-50">
                    <td colSpan={6} className="px-3 py-2 space-y-1">
                      <div>{r.description}</div>
                      <div className="text-slate-500">Auto-response: {r.automated_response?.note}</div>
                      {r.settings?.length > 0 ? (
                        <ul className="list-disc ml-4">
                          {r.settings.map((s) => (
                            <li key={s.name}>
                              {s.name} = <b>{String(s.value)}</b> {s.unit} - source: {s.source}
                              {s.tunable ? ' (tunable)' : ' (fixed)'}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <div className="text-slate-500">{r.settings_note}</div>
                      )}
                      <div className="text-slate-500">Needs: {r.prerequisites?.join('; ')}</div>
                      {r.limitations && <div className="text-slate-500">Limits: {r.limitations}</div>}
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Tuning({ user }) {
  const admin = isAdmin(user)
  const [state, setState] = useState(null)
  const [guidance, setGuidance] = useState(null)
  const [edited, setEdited] = useState({})
  const [preview, setPreview] = useState(null)
  const [reason, setReason] = useState('')
  const [ack, setAck] = useState(false)
  const [msg, setMsg] = useState(null)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    try {
      setState(await getTuning())
      setGuidance(await getRuleGuidance())
      setError(null)
    } catch (e) {
      setError(errorMessage(e))
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  if (error && !state) return <div className="text-xs text-red-600">{error}</div>
  if (!state) return <Loader2 className="h-4 w-4 animate-spin text-slate-400" />

  async function doPreview() {
    setMsg(null)
    setError(null)
    try {
      setPreview(await previewTuning(patchFrom(state.values, edited)))
    } catch (e) {
      setError(errorMessage(e))
    }
  }
  async function doApply() {
    setMsg(null)
    setError(null)
    try {
      const r = await applyTuning({ expected_revision: state.revision, values: patchFrom(state.values, edited), reason, acknowledge_weakening: ack })
      setMsg(`Applied as revision ${r.revision}.`)
      setPreview(null)
      setEdited({})
      setReason('')
      setAck(false)
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }
  async function doRollback() {
    setMsg(null)
    setError(null)
    try {
      const r = await rollbackTuning({ expected_revision: state.revision, reason: reason || 'rollback from dashboard' })
      setMsg(`Rolled back as revision ${r.revision}.`)
      await load()
    } catch (e) {
      setError(errorMessage(e))
    }
  }

  return (
    <div className="space-y-3 text-xs">
      <div>
        Active revision <b>{state.revision}</b> {state.revision === 0 ? '(compiled defaults)' : ''}
      </div>
      {state.load_error && <div className="rounded bg-amber-50 border border-amber-200 text-amber-900 px-3 py-2">{state.load_error}</div>}
      {error && <div role="alert" className="rounded bg-red-50 border border-red-200 text-red-700 px-3 py-2">{error}</div>}
      {msg && <div className="rounded bg-green-50 border border-green-200 text-green-800 px-3 py-2">{msg}</div>}

      <table className="w-full">
        <thead>
          <tr className="text-left text-[10px] font-bold uppercase text-slate-500"><th>Setting</th><th>Current</th><th>Default</th><th>Range</th>{admin && <th>New value</th>}</tr>
        </thead>
        <tbody>
          {state.specs.map((sp) => (
            <tr key={sp.key} className="border-t border-slate-100">
              <td className="py-1"><span className="font-mono">{sp.key}</span><div className="text-slate-500">{sp.description} - {sp.comparison}</div></td>
              <td>{state.values[sp.key]}</td>
              <td>{sp.default}</td>
              <td>{sp.min}..{sp.max}</td>
              {admin && (
                <td>
                  <input aria-label={sp.key} value={edited[sp.key] ?? ''} onChange={(e) => setEdited({ ...edited, [sp.key]: e.target.value })} className="w-24 rounded border border-slate-300 px-1 py-0.5" />
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>

      {!admin && <div className="text-slate-500">Changing thresholds requires the admin role. You can inspect everything here.</div>}
      {admin && (
        <div className="space-y-2">
          <button onClick={doPreview} className="rounded border border-slate-300 px-2 py-1">Preview (changes nothing)</button>
          {preview && (
            <div className="rounded border border-slate-200 bg-white p-2 space-y-1">
              <div className="font-semibold">Preview - not applied</div>
              {preview.errors.length > 0 && <ul className="text-red-700 list-disc ml-4">{preview.errors.map((e) => <li key={e}>{e}</li>)}</ul>}
              {preview.changes.length === 0 && preview.errors.length === 0 && <div>No change.</div>}
              <ul className="list-disc ml-4">{preview.changes.map((c) => <li key={c.key} className={c.weakens_detection ? 'text-amber-800' : ''}>{changeText(c)}</li>)}</ul>
              {preview.requires_acknowledgement && (
                <label className="flex items-center gap-2 text-amber-900">
                  <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} /> I understand this makes at least one rule less sensitive
                </label>
              )}
              <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (required, recorded in the audit history)" maxLength={256} className="w-full rounded border border-slate-300 px-2 py-1" />
              <button onClick={doApply} disabled={!canApply({ user, preview, reason, acknowledged: ack })} className="rounded bg-slate-900 text-white px-2 py-1 disabled:opacity-40">Apply</button>
            </div>
          )}
          {state.revision > 0 && <button onClick={doRollback} className="rounded border border-slate-300 px-2 py-1">Roll back to the previous revision</button>}
        </div>
      )}

      <div>
        <div className="font-bold uppercase tracking-wide text-[10px] text-slate-500">History</div>
        {state.history.length === 0 ? <div className="text-slate-500">No operator changes yet.</div> : (
          <ul className="space-y-0.5">
            {state.history.map((h) => (
              <li key={h.revision}>
                r{h.revision} {h.kind} by {h.actor} ({h.status}) {h.reason ? `- ${h.reason}` : ''}{h.weakening_acknowledged ? ' [weakening acknowledged]' : ''}
                <span className="text-slate-500"> {h.changes.map(changeText).join('; ')}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      {guidance && (
        <div>
          <div className="font-bold uppercase tracking-wide text-[10px] text-slate-500">Guidance (suggestions only, never applied automatically)</div>
          <ul className="space-y-1">
            {guidance.guidance.map((g) => (
              <li key={g.key}><span className="font-mono">{g.rule_id}</span>: {g.recommendation}</li>
            ))}
          </ul>
          <div className="text-slate-500">{guidance.guidance[0]?.basis}</div>
        </div>
      )}
    </div>
  )
}

export default function RulesPage({ user }) {
  const [tab, setTab] = useState('inventory')
  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-4">
      <div className="flex gap-1 border-b border-slate-200">
        {[['inventory', 'Rule inventory'], ['tuning', 'Tuning']].map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)} className={`px-3 py-1.5 text-xs font-semibold border-b-2 ${tab === id ? 'border-slate-900 text-slate-900' : 'border-transparent text-slate-500'}`}>{label}</button>
        ))}
      </div>
      {tab === 'inventory' ? <Inventory /> : <Tuning user={user} />}
    </div>
  )
}
