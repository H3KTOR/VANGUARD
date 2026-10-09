// IntelPage.test.jsx
//
// Guards the honesty rules of the threat-intel UI: expired/disabled
// indicators are never shown as active, import failures are shown as
// "nothing changed", hunt results explain matches without attributing,
// empty and error states are explicit.

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import IntelPage from '../IntelPage.jsx'
import { indicatorWarnings, explainMatch, importSummary, buildHuntQuery } from '../../utils/intel.js'

vi.mock('../../api/vanguardClient.js', () => ({
  getIntelStatus: vi.fn(),
  listIOCs: vi.fn(),
  setIOCEnabled: vi.fn(),
  importIOCs: vi.fn(),
  listIOCImports: vi.fn(),
  huntMatches: vi.fn(),
}))
import * as api from '../../api/vanguardClient.js'

describe('intel helpers', () => {
  it('warns about expired, disabled, low-confidence and unrated indicators', () => {
    expect(indicatorWarnings({ state: 'expired', type: 'ip', confidence: 'high' }).join(' ')).toMatch(/Expired/)
    expect(indicatorWarnings({ state: 'disabled', disabled_by_operator: true, type: 'ip', confidence: 'high' }).join(' ')).toMatch(/operator/)
    expect(indicatorWarnings({ state: 'active', type: 'ip', confidence: 'low' }).join(' ')).toMatch(/Low confidence/)
    expect(indicatorWarnings({ state: 'active', type: 'domain', confidence: '' }).join(' ')).toMatch(/no confidence/)
    expect(indicatorWarnings({ state: 'active', type: 'domain', confidence: 'high' }).join(' ')).toMatch(/Host header/)
    expect(indicatorWarnings(null)).toEqual([])
  })
  it('explains a match without attributing or claiming compromise', () => {
    const text = explainMatch({ field: 'source_ip', ioc_type: 'ip', context: '203.0.113.7', source: 'feed-a', kind: 'direct' })
    expect(text).toMatch(/Exact match/)
    expect(text).toMatch(/does not by itself show compromise or identify the actor/)
    expect(explainMatch({ field: 'source_ip', ioc_type: 'ip', context: 'x', source: 's', kind: 'enrichment' })).toMatch(/Context only/)
  })
  it('summarizes applied and rejected imports truthfully', () => {
    expect(importSummary({ status: 'rejected', error: 'bad' })).toMatch(/nothing was changed/)
    expect(importSummary({ status: 'applied', accepted: 2, updated: 1, duplicate: 0, rejected: 3, expired: 1, disabled: 0 })).toMatch(/2 new.*3 invalid.*1 already expired/)
  })
  it('bounds the hunt limit and drops empty filters', () => {
    expect(buildHuntQuery({ ip: ' ', limit: '9999', kind: 'direct' })).toEqual({ kind: 'direct', limit: '200' })
    expect(buildHuntQuery({ limit: 'abc' }).limit).toBe('50')
  })
})

describe('<IntelPage />', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.getIntelStatus.mockResolvedValue({ enabled: true, indicators_total: 3, indicators_active: 1, matcher: { loaded: true, indicators_loaded: 1 } })
    api.listIOCImports.mockResolvedValue({ imports: [] })
    api.listIOCs.mockResolvedValue({ indicators: [] })
  })

  it('labels indicators by their server-reported state, never "active" for expired/disabled', async () => {
    api.listIOCs.mockResolvedValue({
      indicators: [
        { id: 1, type: 'ip', value: '203.0.113.1', source: 's', state: 'expired', confidence: 'high', expires_at: '2020-01-01T00:00:00Z' },
        { id: 2, type: 'ip', value: '203.0.113.2', source: 's', state: 'disabled', confidence: '' },
        { id: 3, type: 'ip', value: '203.0.113.3', source: 's', state: 'active', confidence: 'medium' },
      ],
    })
    render(<IntelPage />)
    expect(await screen.findByText('203.0.113.1')).toBeTruthy()
    expect(screen.getAllByText('expired').length).toBe(1)
    expect(screen.getAllByText('disabled').length).toBe(1)
    expect(screen.getAllByText('active').length).toBe(1)
    expect(screen.getByText('unrated')).toBeTruthy()
  })

  it('shows an explicit message when the matcher never loaded', async () => {
    api.getIntelStatus.mockResolvedValue({ enabled: true, indicators_total: 0, indicators_active: 0, matcher: { loaded: false, last_error: 'db locked' } })
    render(<IntelPage />)
    expect(await screen.findByText(/no matching is happening/i)).toBeTruthy()
  })

  it('shows a rejected import as "nothing was changed" with the reasons', async () => {
    const err = Object.assign(new Error('import rejected'), { body: { status: 'rejected', error: 'unsupported version 9', reject_sample: [] } })
    api.importIOCs.mockRejectedValue(err)
    render(<IntelPage />)
    fireEvent.click(screen.getByText('Import'))
    fireEvent.change(screen.getByPlaceholderText(/vanguard-ioc/), { target: { value: '{}' } })
    fireEvent.click(screen.getAllByText('Import').pop())
    expect(await screen.findByText(/nothing was changed/i)).toBeTruthy()
    expect(screen.getByText(/unsupported version 9/)).toBeTruthy()
  })

  it('hunt: empty, results with explanation, and error states', async () => {
    render(<IntelPage />)
    fireEvent.click(screen.getByText('Hunt'))
    api.huntMatches.mockResolvedValueOnce({ matches: [] })
    fireEvent.click(screen.getAllByRole('button', { name: /Hunt/ }).pop())
    expect(await screen.findByText(/No recorded matches/)).toBeTruthy()

    api.huntMatches.mockResolvedValueOnce({
      matches: [{ id: 1, matched_at: '2026-10-09T10:00:00Z', ioc_type: 'ip', context: '203.0.113.7', source: 'feed-a', source_ip: '203.0.113.7', field: 'source_ip', kind: 'direct', incident_id: 5, incident_type: 'ioc_match', incident_status: 'open' }],
    })
    fireEvent.click(screen.getAllByRole('button', { name: /Hunt/ }).pop())
    expect(await screen.findByText(/Exact match/)).toBeTruthy()
    expect(screen.getByText(/Incident #5/)).toBeTruthy()

    api.huntMatches.mockRejectedValueOnce(new Error('invalid ip'))
    fireEvent.click(screen.getAllByRole('button', { name: /Hunt/ }).pop())
    await waitFor(() => expect(screen.getByText('invalid ip')).toBeTruthy())
  })
})
