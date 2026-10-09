import { useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { usePolling } from '../hooks/usePolling.js'
import { getRuntimeHealth } from '../api/vanguardClient.js'
import { HEALTH_LABEL, healthAttention, healthHeadline } from '../utils/evidence.js'

// Shown only when VANGUARD's own machinery is not fully healthy. Polls
// slowly (30s) and renders nothing when everything reported a real, recent
// success -- so it is never noise, and never an all-clear it cannot back.
// If the health endpoint itself cannot be reached, that is shown too.
export default function RuntimeHealthBanner() {
  const { data, error } = usePolling(() => getRuntimeHealth(), 30000, [])
  const [open, setOpen] = useState(false)

  if (error && !data) {
    return (
      <div role="alert" className="bg-amber-50 border-b border-amber-200 text-amber-900 text-xs px-6 py-2">
        Runtime health is unavailable ({error.message}) - the state of VANGUARD itself cannot be confirmed.
      </div>
    )
  }
  const headline = healthHeadline(data)
  if (!headline) return null
  const bad = healthAttention(data)
  return (
    <div role="alert" className="bg-amber-50 border-b border-amber-200 text-amber-900 text-xs px-6 py-2">
      <button className="flex items-center gap-2 font-semibold" onClick={() => setOpen(!open)} aria-expanded={open}>
        <AlertTriangle className="h-4 w-4" /> {headline} <span className="underline font-normal">{open ? 'hide' : 'details'}</span>
      </button>
      {open && (
        <ul className="mt-1 space-y-0.5">
          {bad.map((c) => (
            <li key={c.name}>
              <span className="font-mono">{c.name}</span>: {HEALTH_LABEL[c.state] || c.state}
              {c.detail ? ` - ${c.detail}` : ''}
              {c.last_success ? ` (last success ${new Date(c.last_success).toLocaleString()})` : ' (no success recorded)'}
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
