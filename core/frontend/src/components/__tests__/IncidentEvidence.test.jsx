// IncidentEvidence.test.jsx
//
// Guards the wording rules for response status: "verified" may only come
// from a verification event with outcome "verified"; a bare successful
// command is "not verified"; a plan is always labelled "not executed";
// older incidents with no provenance/events render safely.

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import IncidentEvidence from '../IncidentEvidence.jsx'
import { responseSummary, provenanceOf, planLabel, scannerAttention } from '../../utils/evidence.js'

vi.mock('../../api/vanguardClient.js', () => ({
  getIncidentEvents: vi.fn(),
  getResponsePlan: vi.fn(),
}))
import { getIncidentEvents, getResponsePlan } from '../../api/vanguardClient.js'

const ev = (kind, outcome, extra = {}) => ({ id: Math.random(), kind, outcome, at: '2026-10-09T10:00:00Z', ...extra })

describe('responseSummary', () => {
  it('reports none when nothing was recorded', () => {
    expect(responseSummary([]).state).toBe('none')
    expect(responseSummary(null).state).toBe('none')
  })
  it('never calls a bare successful command verified', () => {
    const s = responseSummary([ev('response', 'succeeded')])
    expect(s.state).toBe('unverified')
    expect(s.label).toMatch(/not verified/i)
  })
  it('only a verified verification event yields verified', () => {
    expect(responseSummary([ev('response', 'succeeded'), ev('verification', 'verified')]).state).toBe('verified')
  })
  it('keeps failed and inconclusive verification visible', () => {
    expect(responseSummary([ev('response', 'succeeded'), ev('verification', 'failed')]).state).toBe('verification_failed')
    expect(responseSummary([ev('response', 'succeeded'), ev('verification', 'inconclusive')]).state).toBe('inconclusive')
  })
  it('distinguishes failed / suppressed / not eligible', () => {
    expect(responseSummary([ev('response', 'failed')]).state).toBe('failed')
    expect(responseSummary([ev('response', 'suppressed')]).state).toBe('suppressed')
    expect(responseSummary([ev('response', 'not_eligible')]).state).toBe('not_eligible')
  })
})

describe('provenance / plan / scanner helpers', () => {
  it('handles missing provenance', () => {
    expect(provenanceOf(null)).toBeNull()
    expect(provenanceOf({})).toBeNull()
  })
  it('marks correlated evidence as inferred, everything else as observed', () => {
    expect(provenanceOf({ provenance: { rule_id: 'attack_chain', evidence_kind: 'correlated' } }).kind).toBe('correlated')
    expect(provenanceOf({ provenance: { rule_id: 'port_scan' } }).kind).toBe('observed')
  })
  it('labels a plan as not executed', () => {
    expect(planLabel({ would_ban: true, source_ip: '1.2.3.4', reason: 'r' })).toMatch(/not executed/)
    expect(planLabel({ would_ban: false, reason: 'r' })).toMatch(/not executed/)
    expect(planLabel(null)).toBeNull()
  })
  it('flags only failed / skipped / timed-out scanners', () => {
    const bad = scannerAttention([
      { name: 'a', last_result: 'ok' },
      { name: 'b', last_result: 'failed' },
      { name: 'c', last_result: 'skipped' },
      { name: 'd', last_result: 'timeout' },
      { name: 'e', last_result: 'never_run' },
    ])
    expect(bad.map((d) => d.name)).toEqual(['b', 'c', 'd'])
  })
})

describe('<IncidentEvidence />', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders an old incident with no metadata/events/plan without crashing', async () => {
    getIncidentEvents.mockResolvedValue({ events: [] })
    getResponsePlan.mockRejectedValue(new Error('x'))
    render(<IncidentEvidence incident={{ id: 1, metadata: '' }} />)
    expect(await screen.findByText(/predates Phase 5/i)).toBeTruthy()
    await waitFor(() => expect(screen.getByText(/No automated response recorded/i)).toBeTruthy())
    expect(screen.getByText(/No lifecycle or response events/i)).toBeTruthy()
  })

  it('shows correlated provenance, unverified block and a not-executed plan', async () => {
    getIncidentEvents.mockResolvedValue({
      events: [ev('response', 'succeeded', { id: 1, detail: 'block returned success' })],
    })
    getResponsePlan.mockResolvedValue({ would_ban: false, reason: 'already banned' })
    const meta = JSON.stringify({ provenance: { rule_id: 'attack_chain', rule_revision: 1, evidence_kind: 'correlated', limitations: 'does not prove compromise' } })
    render(<IncidentEvidence incident={{ id: 2, metadata: meta }} />)
    expect(await screen.findByText(/Inferred by correlating/i)).toBeTruthy()
    expect(await screen.findByText(/Block command succeeded; not verified/i)).toBeTruthy()
    expect(await screen.findByText(/Planned \(not executed\)/i)).toBeTruthy()
    expect(screen.queryByText(/Block verified/i)).toBeNull()
  })

  it('surfaces a history load failure', async () => {
    getIncidentEvents.mockRejectedValue(new Error('boom'))
    getResponsePlan.mockRejectedValue(new Error('x'))
    render(<IncidentEvidence incident={{ id: 3, metadata: '{}' }} />)
    expect(await screen.findByText(/Could not load history: boom/i)).toBeTruthy()
  })
})
