import { useCallback, useEffect, useState } from 'react'
import { listBackups, createBackup, verifyBackup } from '../api/vanguardClient.js'
import { backupAgeText, verifyText } from '../utils/backup.js'

// Admin-only panel. It can create and verify backups; it cannot download or
// restore one (restore is an explicit offline CLI action, by design).
export default function BackupPanel() {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [results, setResults] = useState({})
  const [excludeUsers, setExcludeUsers] = useState(false)

  const load = useCallback(async () => {
    try {
      setData(await listBackups())
      setError(null)
    } catch (e) {
      setError(e.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  async function create() {
    setBusy(true)
    try {
      await createBackup({ exclude_users: excludeUsers })
      await load()
    } catch (e) {
      setError(e.message)
    } finally {
      setBusy(false)
    }
  }
  async function verify(name) {
    try {
      setResults({ ...results, [name]: await verifyBackup(name) })
    } catch (e) {
      setResults({ ...results, [name]: { error: e.message } })
    }
  }

  if (error && !data) return <div className="text-xs text-red-600">Backups unavailable: {error}</div>
  if (!data) return null
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-card space-y-3 text-xs">
      <h3 className="text-sm font-bold text-slate-800">Backups</h3>
      <div>{backupAgeText(data.last_backup_at)}</div>
      {error && <div role="alert" className="text-red-600">{error}</div>}
      <div className="flex items-center gap-3">
        <button onClick={create} disabled={busy} className="rounded bg-slate-900 text-white px-2 py-1 disabled:opacity-50">Create backup now</button>
        <label className="flex items-center gap-1"><input type="checkbox" checked={excludeUsers} onChange={(e) => setExcludeUsers(e.target.checked)} /> leave out user accounts</label>
      </div>
      {data.backups.length === 0 ? (
        <div className="text-slate-500">No backups yet.</div>
      ) : (
        <ul className="space-y-1">
          {data.backups.map((b) => (
            <li key={b.name}>
              <span className="font-mono">{b.name}</span> {b.users_included ? '' : '(no user accounts)'}{' '}
              <button className="underline" onClick={() => verify(b.name)}>Verify</button>
              {results[b.name] && <div className={results[b.name].valid ? 'text-green-700' : 'text-red-700'}>{verifyText(results[b.name])}</div>}
            </li>
          ))}
        </ul>
      )}
      <div className="text-slate-500">
        Checksums detect corruption, not tampering; backups are not encrypted. They cannot be downloaded or restored from here: copy them from the host and
        restore with <code>vanguard backup restore</code> while VANGUARD is stopped (see docs/PHASE11.md).
      </div>
    </div>
  )
}
