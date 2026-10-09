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
  getIncidentTimeline: vi.fn(),
  getIncidentGraph: vi.fn(),
  listNotes: vi.fn(),
  addNote: vi.fn(),
  deleteNote: vi.fn(),
  exportIncident: vi.fn(),
}))
import {
  getIncidentEvents,
  getResponsePlan,
  getIncidentTimeline,
  getIncidentGraph,
  listNotes,
  addNote,
  exportIncident,
} from '../../api/vanguardClient.js'
import { fireEvent } from '@testing-library/react'
import { relationText, timelineNotice, downloadName } from '../../utils/evidence.js'

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
    getIncidentTimeline.mockResolvedValue({ total: 0, entries: [], data_gaps: [] })
    getIncidentGraph.mockResolvedValue({ nodes: [], edges: [] })
    listNotes.mockResolvedValue({ notes: [] })
  })

  it('renders an old incident with no metadata/events/plan without crashing', async () => {
    getIncidentEvents.mockResolvedValue({ events: [] })
    getResponsePlan.mockRejectedValue(new Error('x'))
    render(<IncidentEvidence incident={{ id: 1, metadata: '' }} />)
    expect(await screen.findByText(/predates Phase 5/i)).toBeTruthy()
    await waitFor(() => expect(screen.getByText(/No automated response recorded/i)).toBeTruthy())
    expect(screen.getByText(/No persisted records for this incident/i)).toBeTruthy()
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

describe('investigation view', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    getIncidentEvents.mockResolvedValue({ events: [] })
    getResponsePlan.mockRejectedValue(new Error('x'))
    getIncidentGraph.mockResolvedValue({ nodes: [], edges: [] })
    listNotes.mockResolvedValue({ notes: [] })
  })

  it('labels each timeline entry by provenance and discloses data gaps', async () => {
    getIncidentTimeline.mockResolvedValue({
      total: 2,
      entries: [
        { ref: 'incidents#1', at: '2026-10-09T10:00:00Z', provenance: 'correlated', summary: 'Detector attack_chain raised this incident' },
        { ref: 'incident_notes#4', at: '2026-10-09T10:05:00Z', provenance: 'analyst', summary: 'Note by a@x' },
      ],
      data_gaps: ['Raw events and log lines are not retained'],
    })
    render(<IncidentEvidence incident={{ id: 1, metadata: '' }} />)
    expect(await screen.findByText('Correlated (inferred)')).toBeTruthy()
    expect(screen.getByText('Analyst')).toBeTruthy()
    expect(screen.getByText(/What this timeline cannot tell you \(1\)/)).toBeTruthy()
  })

  it('an empty timeline says nothing was persisted, not that nothing happened', async () => {
    getIncidentTimeline.mockResolvedValue({ total: 0, entries: [], data_gaps: [] })
    render(<IncidentEvidence incident={{ id: 2, metadata: '' }} />)
    expect(await screen.findByText(/No persisted records for this incident/)).toBeTruthy()
    expect(screen.getByText(/Closeness in time or address is not used to link incidents/)).toBeTruthy()
  })

  it('related incidents never imply a common actor', async () => {
    getIncidentGraph.mockResolvedValue({ nodes: [], edges: [{ relation: 'shares_indicator', to: 'incident:9', ref: 'ioc_matches#3' }] })
    getIncidentTimeline.mockResolvedValue({ total: 1, entries: [{ ref: 'incidents#3', at: '2026-10-09T10:00:00Z', provenance: 'observed', summary: 's' }], data_gaps: [] })
    render(<IncidentEvidence incident={{ id: 3, metadata: '' }} />)
    expect(await screen.findByText(/does not establish the same actor/)).toBeTruthy()
  })

  it('notes: shows author, renders text literally, and submits trimmed input', async () => {
    listNotes.mockResolvedValueOnce({ notes: [{ id: 1, author: 'a@x', created_at: '2026-10-09T10:00:00Z', text: '<img src=x onerror=alert(1)>' }] })
    addNote.mockResolvedValue({ id: 2 })
    getIncidentTimeline.mockResolvedValue({ total: 0, entries: [], data_gaps: [] })
    const { container } = render(<IncidentEvidence incident={{ id: 4, metadata: '' }} />)
    expect(await screen.findByText('<img src=x onerror=alert(1)>')).toBeTruthy()
    expect(container.querySelector('img')).toBeNull()
    fireEvent.change(screen.getByPlaceholderText(/Add a note/), { target: { value: 'checked' } })
    fireEvent.click(screen.getByText('Add note'))
    await waitFor(() => expect(addNote).toHaveBeenCalledWith(4, 'checked'))
  })

  it('export failure is surfaced', async () => {
    exportIncident.mockRejectedValue(new Error('Export failed (500)'))
    getIncidentTimeline.mockResolvedValue({ total: 0, entries: [], data_gaps: [] })
    render(<IncidentEvidence incident={{ id: 5, metadata: '' }} />)
    fireEvent.click(await screen.findByText(/Export investigation/))
    expect(await screen.findByText(/Export failed \(500\)/)).toBeTruthy()
  })

  it('pure helpers', () => {
    expect(relationText({ relation: 'matched_context', to: 'indicator:2' })).toMatch(/context only/)
    expect(relationText({ relation: 'triggered_response', to: 'response:1' })).toMatch(/firewall rule/)
    expect(timelineNotice({ total: 0 })).toMatch(/No persisted records/)
    expect(timelineNotice({ total: 3 })).toBeNull()
    expect(downloadName('7abc')).toBe('vanguard-incident-0.json')
    expect(downloadName(7)).toBe('vanguard-incident-7.json')
  })
})
