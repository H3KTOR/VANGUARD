// vanguardClient.js
//
// Thin fetch wrapper around the VANGUARD Core Echo REST API
// (see core/internal/api/server.go for the authoritative route table).
//
// Design notes:
//   - Every authenticated call automatically attaches
//     `Authorization: Bearer <token>` from localStorage -- callers never
//     have to think about the header.
//   - A single `request()` core function normalizes error handling: any
//     non-2xx response is thrown as a `VanguardApiError` carrying the
//     HTTP status and the server's `{ "error": "..." }` message, so UI
//     code can do `catch (err) { setError(err.message) }` uniformly.
//   - `BASE_URL` is relative ("/api"), which works unmodified in both
//     environments:
//       - production: the Go binary serves the built frontend AND the API
//         from the same origin (see cmd/vanguard/frontend.go), so relative
//         paths just work.
//       - local dev: vite.config.js proxies `/api/*` to
//         http://localhost:8080, where `vanguard serve` is running.
//   - A 401 response (expired/invalid token) triggers `onUnauthorized()`
//     if one has been registered via `setUnauthorizedHandler`, so the app
//     shell can redirect to the login screen from one central place
//     instead of every call site checking `err.status === 401` itself.

const BASE_URL = '/api'
const TOKEN_KEY = 'vanguard_token'
const USER_KEY = 'vanguard_user'

export class VanguardApiError extends Error {
  constructor(message, status) {
    super(message)
    this.name = 'VanguardApiError'
    this.status = status
  }
}

let unauthorizedHandler = null
export function setUnauthorizedHandler(fn) {
  unauthorizedHandler = fn
}

export function getToken() {
  return localStorage.getItem(TOKEN_KEY)
}

export function getStoredUser() {
  const raw = localStorage.getItem(USER_KEY)
  if (!raw) return null
  try {
    return JSON.parse(raw)
  } catch {
    return null
  }
}

function storeSession(token, user) {
  localStorage.setItem(TOKEN_KEY, token)
  if (user) localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function clearSession() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

async function request(path, { method = 'GET', body, auth = true, signal } = {}) {
  const headers = { 'Content-Type': 'application/json' }
  if (auth) {
    const token = getToken()
    if (token) headers['Authorization'] = `Bearer ${token}`
  }

  let res
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal,
    })
  } catch (networkErr) {
    throw new VanguardApiError('Network error: unable to reach VANGUARD Core', 0)
  }

  let payload = null
  const text = await res.text()
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = null
    }
  }

  if (!res.ok) {
    if (res.status === 401 && auth && typeof unauthorizedHandler === 'function') {
      unauthorizedHandler()
    }
    const message = (payload && payload.error) || `Request failed (${res.status})`
    throw new VanguardApiError(message, res.status)
  }

  return payload
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

export async function login(email, password) {
  const data = await request('/auth/login', {
    method: 'POST',
    body: { email, password },
    auth: false,
  })
  storeSession(data.token, data.user)
  return data
}

export async function register(email, password, role) {
  return request('/auth/register', {
    method: 'POST',
    body: { email, password, role },
    auth: !!getToken(), // public only for the first bootstrap account
  })
}

export function logout() {
  clearSession()
}

export function getMe() {
  return request('/auth/me')
}

export function isAuthenticated() {
  return !!getToken()
}

// ---------------------------------------------------------------------------
// Health / Dashboard
// ---------------------------------------------------------------------------

export function getHealth() {
  return request('/health', { auth: false })
}

export function getDashboardSummary() {
  return request('/dashboard/summary')
}

// ---------------------------------------------------------------------------
// Incidents
// ---------------------------------------------------------------------------

export function listIncidents(filters = {}) {
  const params = new URLSearchParams()
  Object.entries(filters).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== '') params.set(k, v)
  })
  const qs = params.toString()
  return request(`/incidents${qs ? `?${qs}` : ''}`)
}

export function getIncident(id) {
  return request(`/incidents/${id}`)
}

export function updateIncidentStatus(id, status) {
  return request(`/incidents/${id}/status`, { method: 'PUT', body: { status } })
}

export function blockIncidentIP(id, durationMinutes) {
  return request(`/incidents/${id}/block`, {
    method: 'POST',
    body: { duration_minutes: durationMinutes || 0 },
  })
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

export function listFirewallRules(activeOnly = false) {
  return request(`/firewall/rules${activeOnly ? '?active=true' : ''}`)
}

export function manualBlock(ip, reason, durationMinutes) {
  return request('/firewall/block', {
    method: 'POST',
    body: { ip, reason, duration_minutes: durationMinutes || 0 },
  })
}

export function manualUnban(id) {
  return request(`/firewall/unban/${id}`, { method: 'POST' })
}

export function whitelistIP(ip, reason) {
  return request('/firewall/whitelist', { method: 'POST', body: { ip, reason } })
}

export function getFirewallStatus() {
  return request('/firewall/status')
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

export function getLatestMetric() {
  return request('/metrics/latest')
}

export function getMetricsHistory(hours = 1) {
  return request(`/metrics/history?hours=${hours}`)
}

// ---------------------------------------------------------------------------
// Simulation (demo/testing)
// ---------------------------------------------------------------------------

export function listScenarios() {
  return request('/simulate/scenarios')
}

export function runSimulation(scenario, opts = {}) {
  return request(`/simulate/${scenario}`, { method: 'POST', body: opts })
}

// ---------------------------------------------------------------------------
// Panic Mode
// ---------------------------------------------------------------------------

export function getPanicPreview() {
  return request('/panic/preview')
}

export function enterPanicMode(reason, confirmed) {
  return request('/panic/enter', { method: 'POST', body: { reason, confirmed } })
}

export function exitPanicMode() {
  return request('/panic/exit', { method: 'POST' })
}

export function getPanicStatus() {
  return request('/panic/status')
}

export default {
  login,
  register,
  logout,
  getMe,
  isAuthenticated,
  getToken,
  getStoredUser,
  clearSession,
  setUnauthorizedHandler,
  getHealth,
  getDashboardSummary,
  listIncidents,
  getIncident,
  updateIncidentStatus,
  blockIncidentIP,
  listFirewallRules,
  manualBlock,
  manualUnban,
  whitelistIP,
  getFirewallStatus,
  getLatestMetric,
  getMetricsHistory,
  listScenarios,
  runSimulation,
  getPanicPreview,
  enterPanicMode,
  exitPanicMode,
  getPanicStatus,
  VanguardApiError,
}
