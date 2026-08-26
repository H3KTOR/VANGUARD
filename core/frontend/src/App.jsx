import { useEffect, useState } from 'react'
import { Loader2 } from 'lucide-react'
import { useAuth } from './hooks/useAuth.js'
import { usePolling } from './hooks/usePolling.js'
import { getHealth, getPanicStatus } from './api/vanguardClient.js'
import Sidebar from './components/Sidebar.jsx'
import Header from './components/Header.jsx'
import Login from './components/Login.jsx'
import PanicModal from './components/PanicModal.jsx'
import CommandCenter from './components/CommandCenter.jsx'
import IncidentsPage from './components/IncidentsPage.jsx'
import FirewallPage from './components/FirewallPage.jsx'
import HoneypotPage from './components/HoneypotPage.jsx'
import MetricsPage from './components/MetricsPage.jsx'
import SettingsPage from './components/SettingsPage.jsx'

function formatUptime(seconds) {
  if (seconds == null) return '\u2014'
  const d = Math.floor(seconds / 86400)
  const h = Math.floor((seconds % 86400) / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  if (d > 0) return `${d}d ${h}h`
  if (h > 0) return `${h}h ${m}m`
  return `${m}m`
}

// App is the root shell: it owns auth gating, the persistent
// sidebar/header chrome, dark-mode class toggling, the Panic Mode modal,
// and simple client-side page routing (no react-router -- five flat pages
// don't warrant the dependency).
export default function App() {
  const { user, checking, login, logout, isAuthenticated } = useAuth()
  const [page, setPage] = useState('command-center')
  const [dark, setDark] = useState(() => localStorage.getItem('vanguard_theme') === 'dark')
  const [panicOpen, setPanicOpen] = useState(false)

  const { data: health } = usePolling(getHealth, 10000, [isAuthenticated])
  const { data: panicStatus, refresh: refreshPanic } = usePolling(
    () => (isAuthenticated ? getPanicStatus() : Promise.resolve(null)),
    10000,
    [isAuthenticated],
  )

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
    localStorage.setItem('vanguard_theme', dark ? 'dark' : 'light')
  }, [dark])

  if (checking) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50">
        <Loader2 className="h-6 w-6 text-slate-400 animate-spin" />
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Login onSuccess={login} />
  }

  const openIncidentsForBell = 0 // populated live inside CommandCenter/IncidentsPage; header badge kept lightweight

  return (
    <div className="min-h-screen flex bg-slate-50 dark:bg-slate-950">
      <Sidebar
        active={page}
        onSelect={setPage}
        nodeOnline={!!health}
        uptimeLabel={formatUptime(health?.uptime_sec)}
      />

      <div className="flex-1 min-w-0 flex flex-col">
        <Header
          page={page}
          dark={dark}
          onToggleDark={() => setDark((v) => !v)}
          openIncidents={openIncidentsForBell}
          user={user}
          onLogout={logout}
          onPanicClick={() => setPanicOpen(true)}
        />

        {panicStatus?.active && (
          <div className="bg-red-600 text-white text-xs font-semibold px-6 py-2 flex items-center justify-between">
            <span>PANIC MODE ACTIVE &mdash; non-essential inbound traffic is locked down.</span>
          </div>
        )}

        <main className="flex-1 overflow-y-auto">
          {page === 'command-center' && <CommandCenter />}
          {page === 'incidents' && <IncidentsPage />}
          {page === 'firewall' && <FirewallPage />}
          {page === 'honeypot' && <HoneypotPage />}
          {page === 'metrics' && <MetricsPage />}
          {page === 'settings' && <SettingsPage user={user} />}
        </main>
      </div>

      {panicOpen && (
        <PanicModal
          onClose={() => setPanicOpen(false)}
          onActivated={() => refreshPanic()}
        />
      )}
    </div>
  )
}
