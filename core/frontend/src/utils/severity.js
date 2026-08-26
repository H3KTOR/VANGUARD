// Shared severity <-> color/label mapping used across every dashboard
// widget, kept in one place so the four severity colors defined in
// tailwind.config.js (severity.critical/high/medium/low) always line up
// with badges, chart series, and counter cards.

export const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

export const SEVERITY_COLORS = {
  CRITICAL: '#dc2626',
  HIGH: '#ea580c',
  MEDIUM: '#d97706',
  LOW: '#16a34a',
}

export const SEVERITY_BG = {
  CRITICAL: 'bg-red-50 text-red-700 ring-red-600/20',
  HIGH: 'bg-orange-50 text-orange-700 ring-orange-600/20',
  MEDIUM: 'bg-amber-50 text-amber-700 ring-amber-600/20',
  LOW: 'bg-green-50 text-green-700 ring-green-600/20',
}

export const SEVERITY_DOT = {
  CRITICAL: 'bg-red-600',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-amber-500',
  LOW: 'bg-green-600',
}

// Maps a 0-100 composite risk score onto a posture label + color, mirroring
// the Go-side SeverityFromScore bands in internal/database/models.go
// (0-29 LOW, 30-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL) but phrased as a
// system-wide "posture" rather than a single incident's severity.
export function postureFromScore(score) {
  if (score >= 80) return { label: 'CRITICAL', text: 'Active exploitation likely', color: SEVERITY_COLORS.CRITICAL }
  if (score >= 60) return { label: 'ELEVATED', text: 'Multiple high-risk signals', color: SEVERITY_COLORS.HIGH }
  if (score >= 30) return { label: 'GUARDED', text: 'Anomalous activity detected', color: SEVERITY_COLORS.MEDIUM }
  return { label: 'SECURE', text: 'No significant threats detected', color: SEVERITY_COLORS.LOW }
}
