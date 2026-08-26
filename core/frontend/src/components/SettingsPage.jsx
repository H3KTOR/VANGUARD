import { useState } from 'react'
import { Loader2 } from 'lucide-react'
import { getFirewallStatus } from '../api/vanguardClient.js'
import { usePolling } from '../hooks/usePolling.js'

export default function SettingsPage({ user }) {
  const { data, loading } = usePolling(getFirewallStatus, 15000)

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-4">
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-card">
        <h3 className="text-sm font-bold text-slate-800 mb-3">Account</h3>
        <dl className="grid grid-cols-2 gap-3 text-sm">
          <div>
            <dt className="text-[11px] font-semibold text-slate-400 uppercase">Email</dt>
            <dd className="text-slate-800">{user?.email}</dd>
          </div>
          <div>
            <dt className="text-[11px] font-semibold text-slate-400 uppercase">Role</dt>
            <dd className="text-slate-800 capitalize">{user?.role}</dd>
          </div>
        </dl>
      </div>

      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-card">
        <h3 className="text-sm font-bold text-slate-800 mb-3 flex items-center gap-2">
          Firewall Executor Status
          {loading && <Loader2 className="h-3.5 w-3.5 animate-spin text-slate-400" />}
        </h3>
        <pre className="rounded-lg bg-slate-900 text-slate-100 text-xs p-4 overflow-x-auto whitespace-pre-wrap">
          {data?.status || 'No status available.'}
        </pre>
      </div>
    </div>
  )
}
