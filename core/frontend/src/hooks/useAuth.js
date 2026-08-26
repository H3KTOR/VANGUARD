import { useCallback, useEffect, useState } from 'react'
import * as api from '../api/vanguardClient.js'

// useAuth centralizes session state (current user, login/logout) so App.jsx
// and any component can react to auth changes without prop-drilling a
// dozen callbacks. Registers itself as the client's global 401 handler so
// an expired/invalid token anywhere in the app bounces the user back to
// the login screen from one single place.
export function useAuth() {
  const [user, setUser] = useState(() => api.getStoredUser())
  const [checking, setChecking] = useState(true)

  const logout = useCallback(() => {
    api.logout()
    setUser(null)
  }, [])

  useEffect(() => {
    api.setUnauthorizedHandler(() => {
      api.clearSession()
      setUser(null)
    })
  }, [])

  // On mount, if we have a stored token, verify it's still valid by
  // calling /auth/me rather than trusting localStorage blindly (the
  // server may have been restarted with a fresh ephemeral JWT secret,
  // invalidating every previously-issued token).
  useEffect(() => {
    let cancelled = false
    async function verify() {
      if (!api.isAuthenticated()) {
        setChecking(false)
        return
      }
      try {
        await api.getMe()
      } catch {
        if (!cancelled) {
          api.clearSession()
          setUser(null)
        }
      } finally {
        if (!cancelled) setChecking(false)
      }
    }
    verify()
    return () => {
      cancelled = true
    }
  }, [])

  const login = useCallback(async (email, password) => {
    const data = await api.login(email, password)
    setUser(data.user)
    return data.user
  }, [])

  return { user, checking, login, logout, isAuthenticated: !!user }
}
