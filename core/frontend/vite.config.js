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
    // Manual chunking splits the single ~630KB bundle into cacheable,
    // independently-invalidated vendor chunks: react/react-dom rarely
    // change version-to-version, recharts (the largest single dep) is
    // only needed by the chart-heavy Command Center/Metrics pages, and
    // lucide-react icons churn independently of both. Splitting these
    // out means a change to our own app code no longer busts the cache
    // for React/Recharts/Lucide on every deploy, and the initial parse
    // cost for any one chunk drops well under the 500KB warning limit.
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          'vendor-react': ['react', 'react-dom'],
          'vendor-charts': ['recharts'],
          'vendor-icons': ['lucide-react'],
        },
      },
    },
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
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.js'],
    css: true,
  },
})
