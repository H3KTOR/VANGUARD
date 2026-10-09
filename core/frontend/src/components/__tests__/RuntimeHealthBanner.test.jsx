import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import RuntimeHealthBanner from '../RuntimeHealthBanner.jsx'
import { healthAttention, healthHeadline } from '../../utils/evidence.js'

vi.mock('../../api/vanguardClient.js', () => ({ getRuntimeHealth: vi.fn() }))
import { getRuntimeHealth } from '../../api/vanguardClient.js'

const comp = (name, state, extra = {}) => ({ name, state, ...extra })

describe('health helpers', () => {
  it('disabled is a choice, not an alert; unobserved/unknown are alerts', () => {
    const rt = { overall: 'healthy', components: [comp('a', 'healthy'), comp('b', 'disabled'), comp('c', 'unknown'), comp('d', 'not_yet_observed'), comp('e', 'timed_out')] }
    expect(healthAttention(rt).map((c) => c.name)).toEqual(['c', 'd', 'e'])
  })
  it('no headline only when overall is healthy', () => {
    expect(healthHeadline({ overall: 'healthy', components: [] })).toBeNull()
    expect(healthHeadline({ overall: 'failed', components: [comp('x', 'failed')] })).toMatch(/FAILED/)
    expect(healthHeadline({ overall: 'unknown', components: [comp('x', 'unknown')] })).toMatch(/not evidence of a clean host/)
    expect(healthHeadline(null)).toBeNull()
  })
})

describe('<RuntimeHealthBanner />', () => {
  beforeEach(() => vi.clearAllMocks())

  it('renders nothing when everything is genuinely healthy', async () => {
    getRuntimeHealth.mockResolvedValue({ overall: 'healthy', components: [comp('database', 'healthy')] })
    const { container } = render(<RuntimeHealthBanner />)
    await new Promise((r) => setTimeout(r, 20))
    expect(container.textContent).toBe('')
  })

  it('shows degraded components with reasons and last success on demand', async () => {
    getRuntimeHealth.mockResolvedValue({
      overall: 'degraded',
      components: [comp('detector:package_drift', 'degraded', { detail: 'package database unavailable' }), comp('database', 'healthy')],
    })
    render(<RuntimeHealthBanner />)
    fireEvent.click(await screen.findByText(/Runtime DEGRADED/))
    expect(screen.getByText(/package database unavailable/)).toBeTruthy()
    expect(screen.getByText(/no success recorded/)).toBeTruthy()
    expect(screen.queryByText('database')).toBeNull()
  })

  it('an unreachable health endpoint is itself reported', async () => {
    getRuntimeHealth.mockRejectedValue(new Error('Network error'))
    render(<RuntimeHealthBanner />)
    expect(await screen.findByText(/cannot be confirmed/)).toBeTruthy()
  })
})
