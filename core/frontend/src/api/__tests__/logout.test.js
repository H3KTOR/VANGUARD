import { describe, it, expect, vi, beforeEach } from 'vitest'
import { logout, getToken } from '../vanguardClient.js'

const setSession = (t) => localStorage.setItem('vanguard_token', t)

describe('logout', () => {
  beforeEach(() => {
    localStorage.clear()
    vi.restoreAllMocks()
  })

  it('tells the server to end the session BEFORE forgetting the token, and then forgets it', async () => {
    setSession('tok-123')
    const calls = []
    vi.stubGlobal('fetch', vi.fn(async (url, init) => {
      calls.push({ url, method: init.method, auth: init.headers.Authorization, tokenAtCall: getToken() })
      return { ok: true, status: 200, text: async () => '{"message":"signed out"}' }
    }))
    await logout()
    expect(calls).toHaveLength(1)
    expect(calls[0]).toMatchObject({ url: '/api/auth/logout', method: 'POST', auth: 'Bearer tok-123', tokenAtCall: 'tok-123' })
    expect(getToken()).toBeNull()
  })

  it('still clears the local session when the server is unreachable', async () => {
    setSession('tok-456')
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('offline')
    }))
    await logout()
    expect(getToken()).toBeNull()
  })
})
