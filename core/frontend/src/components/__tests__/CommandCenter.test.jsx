// CommandCenter.test.jsx
//
// CommandCenter is the main dashboard: it composes six live-polling
// widgets purely from api/vanguardClient.js responses (see usePolling.js
// -- "load immediately, then refresh on an interval"). Rather than
// standing up a real HTTP server, we mock the vanguardClient module
// entirely and assert on the resulting render states:
//   1. initial render before data resolves (no crash, no phantom counts)
//   2. render after the mocked API resolves (posture score, counters,
//      system health, and the block/investigate action wiring)
//   3. the empty/all-clear state (zero open incidents)
//   4. the block-IP action calling blockIncidentIP with the right args
//
// vi.mock is hoisted above imports by Vitest, so the mocked functions
// are in place before CommandCenter (and usePolling) ever import them.

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import CommandCenter from '../CommandCenter.jsx'
import * as vanguardClient from '../../api/vanguardClient.js'

vi.mock('../../api/vanguardClient.js', () => ({
  getDashboardSummary: vi.fn(),
  getLatestMetric: vi.fn(),
  getMetricsHistory: vi.fn(),
  listIncidents: vi.fn(),
  blockIncidentIP: vi.fn(),
  updateIncidentStatus: vi.fn(),
}))

const BASE_SUMMARY = {
  open_incidents_total: 7,
  open_incidents_by_sev: { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 1 },
  incidents_last_24h: 20,
  active_bans_total: 4,
  tracked_ips: 12,
  panic_mode: { active: false },
}

const BASE_METRIC = {
  metric: {
    cpu_percent: 42,
    memory_percent: 61,
    memory_used_mb: 2048,
    disk_percent: 33,
    active_connections: 18,
    timestamp: new Date().toISOString(),
  },
}

const BASE_HISTORY = { metrics: [] }

const OPEN_INCIDENT = {
  id: 101,
  type: 'ssh_bruteforce',
  source_ip: '185.220.101.5',
  severity: 'CRITICAL',
  status: 'open',
  detected_at: new Date().toISOString(),
}

function mockApiResponses({
  summary = BASE_SUMMARY,
  metric = BASE_METRIC,
  history = BASE_HISTORY,
  recentIncidents = { incidents: [] },
  openIncidents = { incidents: [OPEN_INCIDENT] },
} = {}) {
  vanguardClient.getDashboardSummary.mockResolvedValue(summary)
  vanguardClient.getLatestMetric.mockResolvedValue(metric)
  vanguardClient.getMetricsHistory.mockResolvedValue(history)
  // listIncidents is called twice with different filters (recent-for-density
  // vs. open-for-quick-actions) -- CommandCenter distinguishes them by the
  // `status` filter it passes, so branch the mock on that.
  vanguardClient.listIncidents.mockImplementation((filters = {}) => {
    if (filters.status === 'open') return Promise.resolve(openIncidents)
    return Promise.resolve(recentIncidents)
  })
}

describe('<CommandCenter />', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('renders without crashing before any API call resolves', () => {
    // Never-resolving promises so we can assert the pre-data render is safe.
    vanguardClient.getDashboardSummary.mockReturnValue(new Promise(() => {}))
    vanguardClient.getLatestMetric.mockReturnValue(new Promise(() => {}))
    vanguardClient.getMetricsHistory.mockReturnValue(new Promise(() => {}))
    vanguardClient.listIncidents.mockReturnValue(new Promise(() => {}))

    render(<CommandCenter />)

    expect(screen.getByText('Master Threat Posture')).toBeInTheDocument()
    // Gauge defaults to 0 while summary is still loading (both the gauge's
    // score label and the still-zeroed metric cards render "0", so scope
    // the assertion to the gauge's distinctive text-4xl score span).
    const scoreEl = document.querySelector('span.text-4xl.font-extrabold')
    expect(scoreEl).toHaveTextContent('0')
  })

  it('renders the composite posture score, badges, and severity counters once data resolves', async () => {
    mockApiResponses()
    render(<CommandCenter />)

    // computePostureScore(BASE_SUMMARY) = 1*25 + 2*12 + 3*5 + 1*1.5 = 65.5
    // + banBump = min(4,10)*1.5 = 6  => round(65.5 + 6) = 72 (capped at 100)
    await waitFor(() => expect(screen.getByText('72')).toBeInTheDocument())

    expect(screen.getByText('7 open incidents')).toBeInTheDocument()
    expect(screen.getByText('4 active bans')).toBeInTheDocument()
    expect(screen.getByText('12 IPs tracked')).toBeInTheDocument()

    // Four severity counter tiles, each labeling its severity in the
    // uppercase tile header. "CRITICAL" also appears in the open-incident
    // quick-action row's severity badge, so scope to the counter tiles'
    // distinctive label class to avoid an ambiguous multi-match.
    const counterLabels = Array.from(
      document.querySelectorAll('span.text-\\[11px\\].font-bold.tracking-wide.text-slate-500.uppercase'),
    ).map((el) => el.textContent)
    expect(counterLabels).toEqual(expect.arrayContaining(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']))
  })

  it('shows the "No open incidents" empty state when there are none', async () => {
    mockApiResponses({
      summary: { ...BASE_SUMMARY, open_incidents_total: 0, open_incidents_by_sev: {} },
      openIncidents: { incidents: [] },
    })
    render(<CommandCenter />)

    await waitFor(() => expect(screen.getByText('No open incidents. All clear.')).toBeInTheDocument())
  })

  it('lists an open incident with Investigate/Block actions and calls blockIncidentIP on click', async () => {
    mockApiResponses()
    vanguardClient.blockIncidentIP.mockResolvedValue({ success: true })
    const user = userEvent.setup()

    render(<CommandCenter />)

    await waitFor(() => expect(screen.getByText('185.220.101.5')).toBeInTheDocument())

    const incidentRow = screen.getByText('185.220.101.5').closest('div.flex.items-center.justify-between')
    const blockButton = within(incidentRow).getByRole('button', { name: /block/i })

    await user.click(blockButton)

    await waitFor(() => expect(vanguardClient.blockIncidentIP).toHaveBeenCalledWith(101, 60))
  })

  it('calls updateIncidentStatus with "investigating" when Investigate is clicked', async () => {
    mockApiResponses()
    vanguardClient.updateIncidentStatus.mockResolvedValue({ success: true })
    const user = userEvent.setup()

    render(<CommandCenter />)

    await waitFor(() => expect(screen.getByText('185.220.101.5')).toBeInTheDocument())

    const incidentRow = screen.getByText('185.220.101.5').closest('div.flex.items-center.justify-between')
    const investigateButton = within(incidentRow).getByRole('button', { name: /investigate/i })

    await user.click(investigateButton)

    await waitFor(() =>
      expect(vanguardClient.updateIncidentStatus).toHaveBeenCalledWith(101, 'investigating'),
    )
  })

  it('surfaces an action error banner if blockIncidentIP rejects', async () => {
    mockApiResponses()
    vanguardClient.blockIncidentIP.mockRejectedValue(new Error('Request failed (500)'))
    const user = userEvent.setup()

    render(<CommandCenter />)

    await waitFor(() => expect(screen.getByText('185.220.101.5')).toBeInTheDocument())

    const incidentRow = screen.getByText('185.220.101.5').closest('div.flex.items-center.justify-between')
    const blockButton = within(incidentRow).getByRole('button', { name: /block/i })
    await user.click(blockButton)

    await waitFor(() => expect(screen.getByText('Request failed (500)')).toBeInTheDocument())
  })

  it('renders the PANIC MODE ACTIVE badge when panic_mode.active is true', async () => {
    mockApiResponses({ summary: { ...BASE_SUMMARY, panic_mode: { active: true } } })
    render(<CommandCenter />)

    await waitFor(() => expect(screen.getByText('PANIC MODE ACTIVE')).toBeInTheDocument())
  })

  it('renders the four resource metric cards with values from getLatestMetric', async () => {
    mockApiResponses()
    render(<CommandCenter />)

    await waitFor(() => expect(screen.getByText('CPU')).toBeInTheDocument())
    expect(screen.getByText('RAM')).toBeInTheDocument()
    expect(screen.getByText('DISK')).toBeInTheDocument()
    expect(screen.getByText('NETWORK I/O')).toBeInTheDocument()
    // CPU value (42%) renders as a whole-number string somewhere on the card.
    expect(screen.getByText('42')).toBeInTheDocument()
  })
})
