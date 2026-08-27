// Vitest global setup: extends `expect` with jest-dom's DOM matchers
// (toBeInTheDocument, toHaveTextContent, etc.) for every test file, and
// resets DOM/mocks between tests so component tests never leak state
// into one another.
import '@testing-library/jest-dom/vitest'
import { afterEach } from 'vitest'
import { cleanup } from '@testing-library/react'

// jsdom does not implement ResizeObserver, but Recharts' <ResponsiveContainer>
// (used by AttackDensityChart / ThreatMixChart / the Network sparkline)
// requires it to measure its container on mount. A minimal no-op polyfill
// is sufficient for component tests -- we don't need real resize events,
// just for the effect that registers the observer not to throw.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
global.ResizeObserver = global.ResizeObserver || ResizeObserverStub

afterEach(() => {
  cleanup()
})
