import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import RulesPage from '../RulesPage.jsx'
import { canApply, patchFrom, changeText, autoResponseText, enabledText, errorMessage, isAdmin } from '../../utils/rules.js'

vi.mock('../../api/vanguardClient.js', () => ({
  listRules: vi.fn(),
  getTuning: vi.fn(),
  previewTuning: vi.fn(),
  applyTuning: vi.fn(),
  rollbackTuning: vi.fn(),
  getRuleGuidance: vi.fn(),
}))
import * as api from '../../api/vanguardClient.js'

const admin = { role: 'admin', email: 'a@x' }
const viewer = { role: 'viewer', email: 'v@x' }

describe('rules helpers', () => {
  const okPreview = { errors: [], changes: [{ key: 'k', from: 1, to: 2, weakens_detection: true }], requires_acknowledgement: true }
  it('canApply requires admin, a clean preview, a reason, and acknowledgement for weakening', () => {
    expect(canApply({ user: admin, preview: okPreview, reason: 'r', acknowledged: true })).toBe(true)
    expect(canApply({ user: admin, preview: okPreview, reason: 'r', acknowledged: false })).toBe(false)
    expect(canApply({ user: admin, preview: okPreview, reason: '  ', acknowledged: true })).toBe(false)
    expect(canApply({ user: viewer, preview: okPreview, reason: 'r', acknowledged: true })).toBe(false)
    expect(canApply({ user: admin, preview: { ...okPreview, errors: ['bad'] }, reason: 'r', acknowledged: true })).toBe(false)
    expect(canApply({ user: admin, preview: { ...okPreview, changes: [] }, reason: 'r', acknowledged: true })).toBe(false)
    expect(canApply({ user: admin, preview: null, reason: 'r', acknowledged: true })).toBe(false)
    expect(canApply({ user: admin, preview: { errors: [], changes: [{ key: 'k' }], requires_acknowledgement: false }, reason: 'r', acknowledged: false })).toBe(true)
  })
  it('patchFrom sends only changed integers and never coerces garbage', () => {
    expect(patchFrom({ a: 10, b: 20 }, { a: '10', b: '25' })).toEqual({ b: 25 })
    expect(patchFrom({ a: 10 }, { a: '' })).toEqual({})
    expect(patchFrom({ a: 10 }, { a: 'nine' })).toEqual({ a: 'nine' })
    expect(patchFrom({ a: 10 }, { a: '9.5' })).toEqual({ a: '9.5' })
  })
  it('wording', () => {
    expect(changeText({ key: 'k', from: 1, to: 2, weakens_detection: true })).toMatch(/LESS sensitive/)
    expect(changeText({ key: 'k', from: 2, to: 1, weakens_detection: false })).toMatch(/more sensitive/)
    expect(autoResponseText({ possible: true })).toBe('possible in principle')
    expect(autoResponseText(null)).toBe('unknown')
    expect(enabledText({ enabled: false, disabled_by: '-intel=false' })).toMatch(/disabled \(-intel=false\)/)
    expect(isAdmin(null)).toBe(false)
    expect(errorMessage({ body: { code: 'conflict' } })).toMatch(/changed since you loaded/)
    expect(errorMessage({ body: { code: 'needs_acknowledgement' } })).toMatch(/acknowledgement/)
  })
})

const TUNING = {
  revision: 2,
  values: { ssh_bruteforce_min_attempts: 10 },
  defaults: { ssh_bruteforce_min_attempts: 10 },
  specs: [{ key: 'ssh_bruteforce_min_attempts', rule_id: 'ssh_bruteforce', description: 'failed logins', comparison: 'fires when count > value', default: 10, min: 3, max: 500 }],
  load_error: '',
  history: [{ revision: 2, kind: 'apply', actor: 'a@x', status: 'active', reason: 'tighten', weakening_acknowledged: false, changes: [{ key: 'k', from: 12, to: 10, weakens_detection: false }] }],
}

describe('<RulesPage />', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.getTuning.mockResolvedValue(TUNING)
    api.getRuleGuidance.mockResolvedValue({ guidance: [{ key: 'k', rule_id: 'ssh_bruteforce', recommendation: 'Insufficient evidence', basis: 'Counts are retained incidents only' }] })
    api.listRules.mockResolvedValue({
      notes: ['Rules cannot be disabled individually'],
      rules: [
        { rule_id: 'ssh_bruteforce', category: 'authentication', enabled: true, base_severity: 40, evidence_kind: 'observed', description: 'Many failed SSH logins', automated_response: { possible: true, note: 'possible in principle' }, settings: [{ name: 'min_failed_attempts', value: 10, unit: 'attempts', source: 'compiled default', tunable: true }], prerequisites: ['auth.log readable'], limitations: 'inferred from auth.log lines only' },
        { rule_id: 'ioc_match', category: 'threat_intel', enabled: false, disabled_by: '-intel=false', base_severity: 35, evidence_kind: 'observed', description: 'IOC', automated_response: { possible: false, note: 'capped' }, settings: [], settings_note: 'risk is capped', prerequisites: ['indicators imported'] },
      ],
    })
  })

  it('inventory shows state, the controlling flag, provenance and limits', async () => {
    render(<RulesPage user={viewer} />)
    expect(await screen.findByText('ssh_bruteforce')).toBeTruthy()
    expect(screen.getByText(/disabled \(-intel=false\)/)).toBeTruthy()
    fireEvent.click(screen.getByText('ssh_bruteforce'))
    expect(screen.getByText(/source: compiled default/)).toBeTruthy()
    expect(screen.getByText(/inferred from auth.log lines only/)).toBeTruthy()
  })

  it('a viewer can inspect tuning but has no way to change it', async () => {
    render(<RulesPage user={viewer} />)
    fireEvent.click(await screen.findByText('Tuning'))
    expect(await screen.findByText(/requires the admin role/)).toBeTruthy()
    expect(screen.queryByText(/Preview \(changes nothing\)/)).toBeNull()
    expect(screen.queryByLabelText('ssh_bruteforce_min_attempts')).toBeNull()
    expect(screen.getByText(/Guidance \(suggestions only/)).toBeTruthy()
  })

  it('an admin must preview, acknowledge weakening, and give a reason before Apply is enabled', async () => {
    api.previewTuning.mockResolvedValue({
      errors: [], requires_acknowledgement: true,
      changes: [{ key: 'ssh_bruteforce_min_attempts', from: 10, to: 40, weakens_detection: true }],
    })
    api.applyTuning.mockResolvedValue({ revision: 3 })
    render(<RulesPage user={admin} />)
    fireEvent.click(await screen.findByText('Tuning'))
    fireEvent.change(await screen.findByLabelText('ssh_bruteforce_min_attempts'), { target: { value: '40' } })
    fireEvent.click(screen.getByText(/Preview \(changes nothing\)/))
    expect(await screen.findByText(/LESS sensitive/)).toBeTruthy()
    expect(api.previewTuning).toHaveBeenCalledWith({ ssh_bruteforce_min_attempts: 40 })
    const apply = screen.getByText('Apply')
    expect(apply.disabled).toBe(true)
    fireEvent.change(screen.getByPlaceholderText(/Reason/), { target: { value: 'expected scanner' } })
    expect(apply.disabled).toBe(true) // still needs the acknowledgement
    fireEvent.click(screen.getByLabelText(/makes at least one rule less sensitive/))
    expect(apply.disabled).toBe(false)
    fireEvent.click(apply)
    await waitFor(() => expect(api.applyTuning).toHaveBeenCalledWith({ expected_revision: 2, values: { ssh_bruteforce_min_attempts: 40 }, reason: 'expected scanner', acknowledge_weakening: true }))
    expect(await screen.findByText(/Applied as revision 3/)).toBeTruthy()
  })

  it('shows a concurrent-change conflict instead of failing silently', async () => {
    api.previewTuning.mockResolvedValue({ errors: [], requires_acknowledgement: false, changes: [{ key: 'k', from: 10, to: 5, weakens_detection: false }] })
    api.applyTuning.mockRejectedValue(Object.assign(new Error('x'), { body: { code: 'conflict' } }))
    render(<RulesPage user={admin} />)
    fireEvent.click(await screen.findByText('Tuning'))
    fireEvent.change(await screen.findByLabelText('ssh_bruteforce_min_attempts'), { target: { value: '5' } })
    fireEvent.click(screen.getByText(/Preview \(changes nothing\)/))
    await screen.findByText(/more sensitive/)
    fireEvent.change(screen.getByPlaceholderText(/Reason/), { target: { value: 'r' } })
    fireEvent.click(screen.getByText('Apply'))
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.getByText(/changed since you loaded/)).toBeTruthy()
  })

  it('surfaces ignored stored tuning', async () => {
    api.getTuning.mockResolvedValue({ ...TUNING, load_error: 'stored tuning revision 1 is corrupt; using compiled defaults' })
    render(<RulesPage user={viewer} />)
    fireEvent.click(await screen.findByText('Tuning'))
    expect(await screen.findByText(/is corrupt; using compiled defaults/)).toBeTruthy()
  })
})
