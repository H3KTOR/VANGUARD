// backup.js - pure wording helpers for the backup panel.

export function backupAgeText(lastBackupAt, now = Date.now()) {
  if (!lastBackupAt) return 'No backup has been made yet.'
  const t = Date.parse(lastBackupAt)
  if (Number.isNaN(t)) return 'Last backup time is unreadable.'
  const days = Math.floor((now - t) / 86400000)
  if (days < 1) return 'Last backup: within the last 24 hours.'
  return `Last backup: ${days} day(s) ago.`
}

// verifyText never says "valid" unless the server said so.
export function verifyText(r) {
  if (!r) return ''
  if (r.error) return `Verification could not run: ${r.error}`
  if (r.valid) return 'Valid: checksum, integrity check, row counts and schema compatibility all passed (this does not prove who created it).'
  const p = Array.isArray(r.problems) && r.problems.length ? r.problems.join('; ') : 'unknown problem'
  return `NOT valid: ${p}`
}
