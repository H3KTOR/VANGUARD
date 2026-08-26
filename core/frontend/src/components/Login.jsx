import { useState } from 'react'
import { ShieldCheck, Loader2, AlertCircle } from 'lucide-react'
import { login, register } from '../api/vanguardClient.js'

// Login handles both the normal sign-in flow and the one-time first-run
// admin bootstrap (handleRegister on the Go side auto-promotes the very
// first registered account to admin, see internal/api/handlers_auth.go).
export default function Login({ onSuccess }) {
  const [mode, setMode] = useState('login') // 'login' | 'bootstrap'
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)

  async function submit(e) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      if (mode === 'bootstrap') {
        await register(email, password, 'admin')
      }
      const user = await onSuccess(email, password)
      return user
    } catch (err) {
      setError(err.message || 'Authentication failed')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-slate-50 px-4">
      <div className="w-full max-w-sm">
        <div className="flex flex-col items-center mb-8">
          <div className="h-14 w-14 rounded-2xl bg-slate-900 flex items-center justify-center shadow-card mb-4">
            <ShieldCheck className="h-7 w-7 text-white" strokeWidth={2.25} />
          </div>
          <h1 className="text-xl font-bold text-slate-900 tracking-tight">VANGUARD</h1>
          <p className="text-sm text-slate-500 mt-1">Security Operations Center</p>
        </div>

        <div className="bg-white border border-slate-200 rounded-2xl shadow-card p-6">
          <div className="flex mb-5 rounded-lg bg-slate-100 p-1 text-sm font-medium">
            <button
              type="button"
              onClick={() => setMode('login')}
              className={`flex-1 rounded-md py-1.5 transition-colors ${
                mode === 'login' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500'
              }`}
            >
              Sign In
            </button>
            <button
              type="button"
              onClick={() => setMode('bootstrap')}
              className={`flex-1 rounded-md py-1.5 transition-colors ${
                mode === 'bootstrap' ? 'bg-white text-slate-900 shadow-sm' : 'text-slate-500'
              }`}
            >
              First-Run Setup
            </button>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1.5">Email</label>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="admin@vanguard.local"
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-xs font-semibold text-slate-600 mb-1.5">Password</label>
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-lg border border-slate-300 px-3 py-2 text-sm text-slate-900 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-brand-500 focus:border-transparent"
              />
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-lg bg-red-50 border border-red-100 px-3 py-2 text-xs text-red-700">
                <AlertCircle className="h-4 w-4 flex-shrink-0 mt-0.5" />
                <span>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-slate-900 text-white text-sm font-semibold py-2.5 hover:bg-slate-800 transition-colors disabled:opacity-60"
            >
              {busy && <Loader2 className="h-4 w-4 animate-spin" />}
              {mode === 'bootstrap' ? 'Create Admin Account' : 'Sign In'}
            </button>
          </form>
        </div>
        <p className="text-center text-xs text-slate-400 mt-6">VANGUARD v3.0 &middot; Edge-native IDS/IPS</p>
      </div>
    </div>
  )
}
