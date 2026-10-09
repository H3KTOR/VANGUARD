// intel.js
//
// Pure helpers for the threat-intelligence UI. The wording rules matter:
// an indicator is only "active" if the server says so, warnings are
// explicit, and a match is described as what it is -- an exact listing
// match -- never as attribution or proof of compromise.

export const STATE_STYLE = {
  active: 'bg-green-50 text-green-700 ring-green-200',
  disabled: 'bg-slate-100 text-slate-600 ring-slate-300',
  expired: 'bg-red-50 text-red-700 ring-red-200',
}

// Warnings shown next to an indicator. Order: most important first.
export function indicatorWarnings(ioc) {
  const w = []
  if (!ioc) return w
  if (ioc.state === 'expired') w.push('Expired — this indicator cannot match.')
  if (ioc.state === 'disabled') {
    w.push(ioc.disabled_by_operator ? 'Disabled by an operator — re-imports will not re-enable it.' : 'Disabled — this indicator cannot match.')
  }
  if (ioc.confidence === 'low') w.push('Low confidence per its source — matches are discounted and do not raise other incidents’ risk.')
  if (!ioc.confidence) w.push('The source supplied no confidence rating.')
  if (ioc.type === 'ip') w.push('Address matches can be misleading behind CDNs, proxies or NAT.')
  if (ioc.type === 'domain' || ioc.type === 'url') w.push('Only observable when the web log records the Host header.')
  return w
}

const FIELD_TEXT = {
  source_ip: 'the connecting source address',
  host: 'the logged Host header',
  url: 'the logged Host + request path',
  sha256: 'a SHA-256 computed by VANGUARD for a monitored file',
  remote_addr: 'an outbound address of a flagged process',
}

// explainMatch: why this row matched, in plain, non-attributing terms.
export function explainMatch(m) {
  if (!m) return ''
  const what = FIELD_TEXT[m.field] || m.field
  const base = `Exact match: ${what} equals ${m.ioc_type} indicator ${m.context} (source: ${m.source || 'unknown'}).`
  const kind =
    m.kind === 'enrichment'
      ? ' Context only — an unrelated detector raised the incident and its source address happens to be listed.'
      : ' Direct observation that a locally imported feed lists this value.'
  return base + kind + ' This does not by itself show compromise or identify the actor.'
}

export function importSummary(rep) {
  if (!rep) return ''
  if (rep.status === 'rejected') return `Import rejected — nothing was changed. ${rep.error || ''}`.trim()
  const parts = [
    `${rep.accepted} new`,
    `${rep.updated} updated`,
    `${rep.duplicate} unchanged/duplicate`,
    `${rep.rejected} invalid`,
    `${rep.expired} already expired`,
    `${rep.disabled} stored disabled`,
  ]
  if (rep.removed) parts.push(`${rep.removed} removed (replace)`)
  return `Import applied: ${parts.join(', ')}.`
}

// buildHuntQuery drops empty fields and keeps the server-side bounds
// visible to the user (the server enforces them regardless).
export function buildHuntQuery(f) {
  const q = {}
  Object.entries(f || {}).forEach(([k, v]) => {
    if (v !== undefined && v !== null && String(v).trim() !== '') q[k] = String(v).trim()
  })
  const lim = Number(q.limit)
  if (!Number.isFinite(lim) || lim < 1) q.limit = '50'
  else q.limit = String(Math.min(200, Math.floor(lim)))
  return q
}
