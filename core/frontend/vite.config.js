import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// VANGUARD v3.0 dashboard build config.
//
// outDir is deliberately pointed at ../cmd/vanguard/dist (NOT the default
// ./dist inside this frontend/ folder) so the compiled Go binary can embed
// it directly via `//go:embed dist` in cmd/vanguard/frontend.go. Go's embed
// directive cannot reach outside its own package directory with "..", so
// the build output has to physically land inside cmd/vanguard for the
// embed to work at all.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../cmd/vanguard/dist',
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    // Local `npm run dev` proxies API calls straight to the Go daemon so
    // the dashboard can be iterated on with hot reload without rebuilding
    // the Go binary on every change.
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
    },
  },
})
