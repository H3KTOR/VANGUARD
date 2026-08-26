import { useState } from 'react'
import { Ban, ShieldCheck, Plus, Loader2 } from 'lucide-react'
import { usePolling } from '../hooks/usePolling.js'
import { listFirewallRules, manualBlock, manualUnban, whitelistIP } from '../api/vanguardClient.js'

export default function FirewallPage() {
  const [activeOnly, setActiveOnly] = useState(true)
  const { data, refresh, loading } = usePolling(() => listFirewallRules(activeOnly), 6000, [activeOnly])
  const rules = data?.rules || []

  const [showForm, setShowForm] = useState(false)
  const [ip, setIp] = useState('')
  const [reason, setReason] = useState('')
  const [duration, setDuration] = useState(60)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [busyId, setBusyId] = useState(null)

  async function submitBlock(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      await manualBlock(ip, reason, duration)
      setIp('')
      setReason('')
      setShowForm(false)
      await refresh()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }

  async function doUnban(id) {
    setBusyId(id)
    try {
      await manualUnban(id)
      await refresh()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyId(null)
    }
  }

  async function doWhitelist(ipAddr) {
    setBusyId(ipAddr)
    try {
      await whitelistIP(ipAddr, 'Whitelisted via dashboard')
      await refresh()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusyId(null)
    }
  }

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <label className="flex items-center gap-2 text-xs font-medium text-slate-600">
          <input type="checkbox" checked={activeOnly} onChange={(e) => setActiveOnly(e.target.checked)} className="rounded" />
          Active bans only
        </label>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="flex items-center gap-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold px-3 py-2"
        >
          <Plus className="h-3.5 w-3.5" /> Manual Block
        </button>
      </div>

      {showForm && (
        <form onSubmit={submitBlock} className="rounded-xl border border-slate-200 bg-white p-4 shadow-card grid grid-cols-1 sm:grid-cols-4 gap-3 items-end">
          <div className="sm:col-span-2">
            <label className="block text-[11px] font-semibold text-slate-500 mb-1">IP Address</label>
            <input
              required
              value={ip}
              onChange={(e) => setIp(e.target.value)}
              placeholder="203.0.113.5"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-mono"
            />
          </div>
          <div>
            <label className="block text-[11px] font-semibold text-slate-500 mb-1">Duration (min)</label>
            <input
              type="number"
              min={1}
              value={duration}
              onChange={(e) => setDuration(Number(e.target.value))}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            />
          </div>
          <div>
            <label className="block text-[11px] font-semibold text-slate-500 mb-1">Reason</label>
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Optional"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm"
            />
          </div>
          <div className="sm:col-span-4 flex justify-end">
            <button
              type="submit"
              disabled={busy}
              className="flex items-center gap-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-semibold px-4 py-2 disabled:opacity-50"
            >
              {busy && <Loader2 className="h-3.5 w-3.5 animate-spin" />} Block IP
            </button>
          </div>
        </form>
      )}

      {error && <div className="rounded-lg bg-red-50 border border-red-200 text-red-700 text-xs px-4 py-2.5">{error}</div>}

      <div className="rounded-xl border border-slate-200 bg-white shadow-card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-slate-100 bg-slate-50 text-left text-[11px] font-bold uppercase tracking-wide text-slate-500">
              <th className="px-4 py-2.5">IP Address</th>
              <th className="px-4 py-2.5">Reason</th>
              <th className="px-4 py-2.5">Source</th>
              <th className="px-4 py-2.5">Status</th>
              <th className="px-4 py-2.5">Banned At</th>
              <th className="px-4 py-2.5">Unban At</th>
              <th className="px-4 py-2.5 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {rules.map((r) => (
              <tr key={r.id} className="hover:bg-slate-50/60">
                <td className="px-4 py-2.5 font-mono text-xs text-slate-800">{r.ip_address}</td>
                <td className="px-4 py-2.5 text-slate-600 max-w-xs truncate">{r.reason}</td>
                <td className="px-4 py-2.5">
                  <span className="text-[10px] font-bold uppercase text-slate-500 bg-slate-100 px-1.5 py-0.5 rounded">
                    {r.source}
                  </span>
                </td>
                <td className="px-4 py-2.5">
                  {r.is_whitelisted ? (
                    <span className="text-[11px] font-semibold text-green-600">Whitelisted</span>
                  ) : r.is_active ? (
                    <span className="text-[11px] font-semibold text-red-600">Active</span>
                  ) : (
                    <span className="text-[11px] font-semibold text-slate-400">Expired</span>
                  )}
                </td>
                <td className="px-4 py-2.5 text-slate-400 text-xs">{new Date(r.banned_at).toLocaleString()}</td>
                <td className="px-4 py-2.5 text-slate-400 text-xs">
                  {r.unban_at ? new Date(r.unban_at).toLocaleString() : 'Permanent'}
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex items-center justify-end gap-1.5">
                    {r.is_active && !r.is_whitelisted && (
                      <button
                        disabled={busyId === r.id}
                        onClick={() => doUnban(r.id)}
                        title="Unban"
                        className="h-7 w-7 flex items-center justify-center rounded-md bg-slate-100 hover:bg-slate-200 text-slate-600"
                      >
                        <Ban className="h-3.5 w-3.5" />
                      </button>
                    )}
                    {!r.is_whitelisted && (
                      <button
                        disabled={busyId === r.ip_address}
                        onClick={() => doWhitelist(r.ip_address)}
                        title="Whitelist"
                        className="h-7 w-7 flex items-center justify-center rounded-md bg-green-50 hover:bg-green-100 text-green-600"
                      >
                        <ShieldCheck className="h-3.5 w-3.5" />
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
            {rules.length === 0 && !loading && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-sm text-slate-400">
                  No firewall rules found.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
