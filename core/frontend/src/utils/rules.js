// rules.js - pure helpers for the Detection Rules page.

export function isAdmin(user) {
  return !!user && user.role === 'admin'
}

// canApply: the Apply button is enabled only for an admin, with a valid
// preview (no errors, at least one change), a reason, and - when any change
// makes a rule less sensitive - the explicit acknowledgement.
export function canApply({ user, preview, reason, acknowledged }) {
  if (!isAdmin(user) || !preview) return false
  if (!Array.isArray(preview.errors) || preview.errors.length > 0) return false
  if (!Array.isArray(preview.changes) || preview.changes.length === 0) return false
  if (!reason || !reason.trim()) return false
  if (preview.requires_acknowledgement && !acknowledged) return false
  return true
}

export function changeText(c) {
  const dir = c.weakens_detection ? 'LESS sensitive' : 'more sensitive'
  return `${c.key}: ${c.from} -> ${c.to} (${dir})`
}

// patchFrom builds the request patch containing only fields that differ
// from the current values, as integers.
export function patchFrom(current, edited) {
  const out = {}
  Object.keys(edited || {}).forEach((k) => {
    const raw = edited[k]
    if (raw === '' || raw === undefined || raw === null) return
    const n = Number(raw)
    if (Number.isInteger(n) && n !== current[k]) out[k] = n
    else if (!Number.isInteger(n)) out[k] = raw // let the server reject it; never coerce silently
  })
  return out
}

export function autoResponseText(r) {
  if (!r) return 'unknown'
  return r.possible ? 'possible in principle' : 'not possible'
}

export function enabledText(rule) {
  return rule.enabled ? 'enabled' : `disabled (${rule.disabled_by || 'by configuration'})`
}

export function errorMessage(e) {
  if (e && e.body && e.body.code === 'conflict') return 'The configuration changed since you loaded it. Reload and review before retrying.'
  if (e && e.body && e.body.code === 'needs_acknowledgement') return 'This change makes a rule less sensitive and needs the acknowledgement box ticked.'
  return (e && e.message) || 'Request failed'
}
