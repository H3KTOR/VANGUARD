import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import BackupPanel from '../BackupPanel.jsx'
import { backupAgeText, verifyText } from '../../utils/backup.js'

vi.mock('../../api/vanguardClient.js', () => ({
  listBackups: vi.fn(),
  createBackup: vi.fn(),
  verifyBackup: vi.fn(),
}))
import * as api from '../../api/vanguardClient.js'

describe('backup helpers', () => {
  it('age wording', () => {
    const now = Date.parse('2026-10-10T12:00:00Z')
    expect(backupAgeText('', now)).toMatch(/No backup has been made/)
    expect(backupAgeText('garbage', now)).toMatch(/unreadable/)
    expect(backupAgeText('2026-10-10T01:00:00Z', now)).toMatch(/within the last 24 hours/)
    expect(backupAgeText('2026-10-03T12:00:00Z', now)).toMatch(/7 day/)
  })
  it('never calls a backup valid unless the server did, and never claims authenticity', () => {
    expect(verifyText({ valid: true })).toMatch(/does not prove who created it/)
    expect(verifyText({ valid: false, problems: ['SHA-256 mismatch'] })).toMatch(/NOT valid: SHA-256 mismatch/)
    expect(verifyText({ valid: false })).toMatch(/NOT valid/)
    expect(verifyText({ error: 'boom' })).toMatch(/could not run/)
    expect(verifyText(undefined)).toBe('')
  })
})

describe('<BackupPanel />', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    api.listBackups.mockResolvedValue({
      backups: [{ name: 'vanguard-backup-20261009T120000Z', users_included: false }],
      last_backup_at: '2026-10-09T12:00:00Z',
    })
  })

  it('lists backups, states the restore/authenticity limits, and offers no download or restore', async () => {
    render(<BackupPanel />)
    expect(await screen.findByText('vanguard-backup-20261009T120000Z')).toBeTruthy()
    expect(screen.getByText(/no user accounts/)).toBeTruthy()
    expect(screen.getByText(/cannot be downloaded or restored from here/)).toBeTruthy()
    expect(screen.queryByText(/Restore$/)).toBeNull()
    expect(screen.queryByText(/Download/)).toBeNull()
  })

  it('shows a failed verification as NOT valid', async () => {
    api.verifyBackup.mockResolvedValue({ valid: false, problems: ['SHA-256 mismatch: modified'] })
    render(<BackupPanel />)
    fireEvent.click(await screen.findByText('Verify'))
    expect(await screen.findByText(/NOT valid: SHA-256 mismatch/)).toBeTruthy()
  })

  it('create passes the exclude-users choice and reloads; errors are surfaced', async () => {
    api.createBackup.mockResolvedValueOnce({ name: 'x' }).mockRejectedValueOnce(new Error('too many backups'))
    render(<BackupPanel />)
    fireEvent.click(await screen.findByLabelText(/leave out user accounts/))
    fireEvent.click(screen.getByText('Create backup now'))
    await waitFor(() => expect(api.createBackup).toHaveBeenCalledWith({ exclude_users: true }))
    fireEvent.click(screen.getByText('Create backup now'))
    expect(await screen.findByRole('alert')).toBeTruthy()
    expect(screen.getByText(/too many backups/)).toBeTruthy()
  })

  it('a non-admin (403) sees an unavailable message, not controls', async () => {
    api.listBackups.mockRejectedValue(new Error('admin role required for this action'))
    render(<BackupPanel />)
    expect(await screen.findByText(/Backups unavailable/)).toBeTruthy()
    expect(screen.queryByText('Create backup now')).toBeNull()
  })
})
