import { useEffect, useRef, useState, useCallback } from 'react'

// usePolling(fetcher, intervalMs)
//
// Generic "load now, then refresh on an interval" hook used by every
// live widget on the Command Center dashboard. Kept deliberately small:
// no external data-fetching library is pulled in just to poll a handful
// of lightweight JSON endpoints every few seconds.
//
// Returns { data, error, loading, refresh } where `loading` is only true
// for the very first fetch -- subsequent polls update `data`/`error`
// silently in the background so the UI never flashes a spinner every
// few seconds.
export function usePolling(fetcher, intervalMs = 5000, deps = []) {
  const [data, setData] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const fetcherRef = useRef(fetcher)
  fetcherRef.current = fetcher

  const refresh = useCallback(async () => {
    try {
      const result = await fetcherRef.current()
      setData(result)
      setError(null)
    } catch (err) {
      setError(err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    let timer = null

    async function tick() {
      if (cancelled) return
      await refresh()
      if (!cancelled) timer = setTimeout(tick, intervalMs)
    }
    tick()

    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [intervalMs, ...deps])

  return { data, error, loading, refresh }
}
