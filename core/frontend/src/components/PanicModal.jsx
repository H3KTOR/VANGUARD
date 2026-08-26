import { useEffect, useState } from 'react'
import { Siren, AlertTriangle, Loader2, X } from 'lucide-react'
import { getPanicPreview, enterPanicMode } from '../api/vanguardClient.js'

// PanicModal implements the mandatory two-step confirmation flow the Go
// backend enforces (Autopilot.EnterPanicMode rejects confirmed=false
// outright): step 1 shows the dry-run preview of exactly what will stay
// reachable (admin IP + whitelist) so the operator can't lock themselves
// out blind, step 2 is an explicit "type PANIC to confirm" gate.
export default function PanicModal({ onClose, onActivated }) {
  const [preview, setPreview] = useState(null)
  const [loadingPreview, setLoadingPreview] = useState(true)
  const [confirmText, setConfirmText] = useState('')
  const [reason, setReason] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    getPanicPreview()
      .then((p) => !cancelled && setPreview(p))
      .catch((e) => !cancelled && setError(e.message))
      .finally(() => !cancelled && setLoadingPreview(false))
    return () => {
      cancelled = true
    }
  }, [])

  async function activate() {
    setBusy(true)
    setError(null)
    try {
      await enterPanicMode(reason || 'Manual activation via dashboard', true)
      onActivated?.()
      onClose()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }

  const canConfirm = confirmText.trim().toUpperCase() === 'PANIC'

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/50 backdrop-blur-sm px-4">
      <div className="w-full max-w-md rounded-2xl bg-white shadow-xl border border-slate-200 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 bg-red-600 text-white">
          <div className="flex items-center gap-2">
            <Siren className="h-5 w-5" />
            <h2 className="font-bold text-sm">Activate Panic Mode</h2>
          </div>
          <button onClick={onClose} className="text-white/80 hover:text-white">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          <div className="flex gap-2 rounded-lg bg-amber-50 border border-amber-200 px-3 py-2.5 text-xs text-amber-800">
            <AlertTriangle className="h-4 w-4 flex-shrink-0 mt-0.5" />
            <p>
              This will lock down all non-essential inbound traffic at the OS firewall level. Only
              your current admin IP and whitelisted addresses will remain reachable.
            </p>
          </div>

          <div>
            <p className="text-xs font-semibold text-slate-600 mb-1.5">Dry-run preview</p>
            {loadingPreview ? (
              <div className="flex items-center gap-2 text-xs text-slate-400 py-2">
                <Loader2 className="h-3.5 w-3.5 animate-spin" /> Loading preview...
              </div>
            ) : preview ? (
              <div className="rounded-lg border border-slate-200 divide-y divide-slate-100 text-xs">
                <div className="flex justify-between px-3 py-2">
                  <span className="text-slate-500">Admin IP (stays open)</span>
                  <span className="font-mono font-semibold text-slate-800">{preview.admin_ip}</span>
                </div>
                <div className="flex justify-between px-3 py-2">
                  <span className="text-slate-500">Whitelisted IPs preserved</span>
                  <span className="font-semibold text-slate-800">{preview.whitelisted_ip_count ?? 0}</span>
                </div>
                <div className="flex justify-between px-3 py-2">
                  <span className="text-slate-500">Active connections to be dropped</span>
                  <span className="font-semibold text-slate-800">{preview.active_bans_preserved ?? '\u2014'}</span>
                </div>
              </div>
            ) : (
              <p className="text-xs text-red-500">Unable to load preview.</p>
            )}
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">Reason (optional)</label>
            <input
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Active exploitation confirmed on port 22"
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500"
            />
          </div>

          <div>
            <label className="block text-xs font-semibold text-slate-600 mb-1.5">
              Type <span className="font-mono text-red-600">PANIC</span> to confirm
            </label>
            <input
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-red-500"
            />
          </div>

          {error && <p className="text-xs text-red-600">{error}</p>}
        </div>

        <div className="flex gap-2 px-5 py-4 border-t border-slate-100 bg-slate-50">
          <button
            onClick={onClose}
            className="flex-1 rounded-lg border border-slate-300 bg-white py-2 text-sm font-semibold text-slate-700 hover:bg-slate-100"
          >
            Cancel
          </button>
          <button
            onClick={activate}
            disabled={!canConfirm || busy}
            className="flex-1 flex items-center justify-center gap-1.5 rounded-lg bg-red-600 py-2 text-sm font-bold text-white hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {busy && <Loader2 className="h-4 w-4 animate-spin" />}
            Activate Lockdown
          </button>
        </div>
      </div>
    </div>
  )
}
