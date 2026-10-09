// evidence.js
//
// Pure helpers that turn an incident's stored metadata and audit events
// into analyst-facing statements. Kept free of React so the wording rules
// (what may be called "verified") are unit-testable.

export function parseMetadata(raw) {
  if (!raw) return null
  try {
    const v = JSON.parse(raw)
    return v && typeof v === 'object' ? v : null
  } catch {
    return null
  }
}

// Older incidents (pre-Phase 5) have no provenance block.
export function provenanceOf(meta) {
  const p = meta && meta.provenance
  if (!p || typeof p !== 'object') return null
  return {
    ruleId: p.rule_id || null,
    revision: p.rule_revision ?? null,
    kind: p.evidence_kind === 'correlated' ? 'correlated' : 'observed',
    limitations: p.limitations || null,
  }
}

export const KIND_LABEL = {
  observed: 'Observed directly by a single detector',
  correlated: 'Inferred by correlating several observations',
}

// responseSummary reduces the audit trail to ONE honest status. "verified"
// is only ever produced by a verification event with outcome "verified";
// a successful firewall command alone is "applied, not verified".
export function responseSummary(events) {
  const evs = Array.isArray(events) ? events : []
  const responses = evs.filter((e) => e.kind === 'response')
  const verifs = evs.filter((e) => e.kind === 'verification')
  if (responses.length === 0 && verifs.length === 0) {
    return { state: 'none', label: 'No automated response recorded' }
  }
  const lastVerif = verifs[verifs.length - 1]
  if (lastVerif) {
    if (lastVerif.outcome === 'verified') return { state: 'verified', label: 'Block verified in firewall state' }
    if (lastVerif.outcome === 'failed') return { state: 'verification_failed', label: 'Block NOT confirmed — verification failed' }
    return { state: 'inconclusive', label: 'Block applied; verification inconclusive' }
  }
  const lastResp = responses[responses.length - 1]
  switch (lastResp.outcome) {
    case 'succeeded':
      return { state: 'unverified', label: 'Block command succeeded; not verified' }
    case 'failed':
      return { state: 'failed', label: 'Response failed' }
    case 'suppressed':
      return { state: 'suppressed', label: 'Response suppressed by policy' }
    case 'not_eligible':
      return { state: 'not_eligible', label: 'Not eligible for automated response' }
    default:
      return { state: 'unknown', label: 'Response outcome unknown' }
  }
}

// planLabel keeps a preview visibly distinct from an executed action.
export function planLabel(plan) {
  if (!plan) return null
  const prefix = 'Planned (not executed): '
  return plan.would_ban ? `${prefix}would ban ${plan.source_ip} — ${plan.reason}` : `${prefix}no action — ${plan.reason}`
}

export const BAD_SCAN_RESULTS = new Set(['failed', 'skipped', 'timeout'])

export function scannerAttention(detectors) {
  return (Array.isArray(detectors) ? detectors : []).filter((d) => BAD_SCAN_RESULTS.has(d.last_result))
}

// ---------------------------------------------------------------------------
// Phase 7: investigation view helpers
// ---------------------------------------------------------------------------

export const PROVENANCE_LABEL = {
  observed: 'Observed',
  derived: 'Derived context',
  correlated: 'Correlated (inferred)',
  analyst: 'Analyst',
  response: 'Response',
}

export const PROVENANCE_STYLE = {
  observed: 'bg-green-50 text-green-700 ring-green-200',
  derived: 'bg-slate-100 text-slate-600 ring-slate-300',
  correlated: 'bg-amber-50 text-amber-800 ring-amber-200',
  analyst: 'bg-blue-50 text-blue-700 ring-blue-200',
  response: 'bg-purple-50 text-purple-700 ring-purple-200',
}

// relationText renders a graph edge without upgrading it to attribution.
export function relationText(edge) {
  if (!edge) return ''
  const to = edge.to || ''
  switch (edge.relation) {
    case 'matched':
      return `matched indicator ${to} (direct observation)`
    case 'matched_context':
      return `source address listed by ${to} (context only)`
    case 'triggered_response':
      return `a firewall rule (${to}) was created for it`
    case 'shares_indicator':
      return `also matched the same indicator as ${to} — does not establish the same actor`
    default:
      return `${edge.relation} ${to}`
  }
}

// timelineNotice: never let an empty list read as "nothing happened".
export function timelineNotice(tl) {
  if (!tl) return null
  if (tl.total === 0) return 'No persisted records for this incident.'
  return null
}

export function downloadName(id) {
  return `vanguard-incident-${Number(id) || 0}.json`
}

// ---------------------------------------------------------------------------
// Phase 9: runtime health helpers
// ---------------------------------------------------------------------------

export const HEALTH_LABEL = {
  healthy: 'Healthy',
  degraded: 'Degraded',
  failed: 'Failed',
  timed_out: 'Timed out',
  disabled: 'Disabled by configuration',
  not_yet_observed: 'Not yet observed',
  unknown: 'Unknown - no recent telemetry',
}

// States an operator should look at. `disabled` is a deliberate choice and
// not an alert; healthy needs no banner.
export const HEALTH_ATTENTION = new Set(['degraded', 'failed', 'timed_out', 'unknown', 'not_yet_observed'])

export function healthAttention(rt) {
  const comps = Array.isArray(rt && rt.components) ? rt.components : []
  return comps.filter((c) => HEALTH_ATTENTION.has(c.state))
}

// healthHeadline never says "all clear": it returns null only when overall
// is genuinely healthy.
export function healthHeadline(rt) {
  if (!rt) return null
  if (rt.overall === 'healthy') return null
  const n = healthAttention(rt).length
  if (rt.overall === 'unknown' || rt.overall === 'not_yet_observed') {
    return `${n} component(s) have not reported recently - absence of alerts is not evidence of a clean host`
  }
  const kind = rt.overall === 'failed' ? 'FAILED' : rt.overall === 'timed_out' ? 'TIMED OUT' : 'DEGRADED'
  return `Runtime ${kind}: ${n} component(s) need attention`
}
