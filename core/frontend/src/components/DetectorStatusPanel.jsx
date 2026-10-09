import { AlertTriangle } from 'lucide-react'
import { usePolling } from '../hooks/usePolling.js'
import { getDetectorStatus } from '../api/vanguardClient.js'
import { scannerAttention } from '../utils/evidence.js'

// Surfaces scanners that failed, were skipped or timed out. Silence from a
// scanner that is not actually running must not look like a clean host.
export default function DetectorStatusPanel() {
  const { data } = usePolling(() => getDetectorStatus(), 15000, [])
  if (!data) return null
  if (data.enabled === false) {
    return (
      <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-xs text-amber-800 flex items-center gap-2">
        <AlertTriangle className="h-4 w-4" /> Host security scanning is disabled — no host findings will be produced.
      </div>
    )
  }
  const bad = scannerAttention(data.detectors)
  if (bad.length === 0) return null
  return (
    <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-2 text-xs text-amber-900 space-y-1" role="alert">
      <div className="flex items-center gap-2 font-semibold">
        <AlertTriangle className="h-4 w-4" /> {bad.length} scanner(s) not completing cleanly — absence of findings from these is not evidence of a clean host
      </div>
      <ul>
        {bad.map((d) => (
          <li key={d.name}>
            <span className="font-mono">{d.name}</span>: {d.last_result}
            {d.last_note ? ` — ${d.last_note}` : ''}
          </li>
        ))}
      </ul>
    </div>
  )
}
