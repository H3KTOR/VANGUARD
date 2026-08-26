import { useState } from 'react'
import { Sun, Moon, Bell, ChevronDown, LogOut, Siren, User } from 'lucide-react'

const TITLES = {
  'command-center': ['Command Center', 'Real-time threat overview & system posture'],
  incidents: ['Incidents', 'Full detection history & triage queue'],
  firewall: ['Firewall Rules', 'Active bans, whitelist, and manual controls'],
  honeypot: ['Honeypot', 'Decoy service activity'],
  metrics: ['System Metrics', 'Host resource utilization over time'],
  settings: ['Settings', 'Account & platform configuration'],
}

// Header: top bar with the current section's title/subtitle, a
// light/dark theme toggle, an incident-count notification bell, the red
// "Panic Mode" trigger, and a user menu with sign-out.
export default function Header({ page, dark, onToggleDark, openIncidents, user, onLogout, onPanicClick }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const [title, subtitle] = TITLES[page] || ['VANGUARD', '']

  return (
    <header className="sticky top-0 z-20 flex items-center justify-between h-16 px-6 border-b border-slate-200 bg-white/80 backdrop-blur">
      <div>
        <h1 className="text-lg font-bold text-slate-900 leading-tight">{title}</h1>
        <p className="text-xs text-slate-400">{subtitle}</p>
      </div>

      <div className="flex items-center gap-2">
        <button
          onClick={onPanicClick}
          className="hidden sm:flex items-center gap-1.5 rounded-lg bg-red-600 hover:bg-red-700 text-white text-xs font-bold px-3 py-2 transition-colors shadow-sm"
        >
          <Siren className="h-3.5 w-3.5" />
          PANIC MODE
        </button>

        <button
          className="relative h-9 w-9 flex items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100 transition-colors"
          title={`${openIncidents} open incidents`}
        >
          <Bell className="h-[18px] w-[18px]" />
          {openIncidents > 0 && (
            <span className="absolute -top-0.5 -right-0.5 h-4 min-w-[16px] px-0.5 rounded-full bg-red-600 text-white text-[9px] font-bold flex items-center justify-center">
              {openIncidents > 99 ? '99+' : openIncidents}
            </span>
          )}
        </button>

        <button
          onClick={onToggleDark}
          className="h-9 w-9 flex items-center justify-center rounded-lg text-slate-500 hover:bg-slate-100 transition-colors"
          title="Toggle theme"
        >
          {dark ? <Sun className="h-[18px] w-[18px]" /> : <Moon className="h-[18px] w-[18px]" />}
        </button>

        <div className="relative">
          <button
            onClick={() => setMenuOpen((v) => !v)}
            className="flex items-center gap-2 pl-2 pr-2.5 py-1.5 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <div className="h-7 w-7 rounded-full bg-brand-600 flex items-center justify-center text-white text-xs font-bold">
              {(user?.email || '?').slice(0, 1).toUpperCase()}
            </div>
            <div className="hidden md:block text-left leading-tight">
              <p className="text-xs font-semibold text-slate-800 max-w-[140px] truncate">{user?.email}</p>
              <p className="text-[10px] text-slate-400 capitalize">{user?.role}</p>
            </div>
            <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
          </button>

          {menuOpen && (
            <>
              <div className="fixed inset-0 z-10" onClick={() => setMenuOpen(false)} />
              <div className="absolute right-0 mt-2 w-48 rounded-xl border border-slate-200 bg-white shadow-lg py-1.5 z-20">
                <div className="px-3 py-2 border-b border-slate-100">
                  <p className="text-xs font-semibold text-slate-800 truncate flex items-center gap-1.5">
                    <User className="h-3 w-3" /> {user?.email}
                  </p>
                </div>
                <button
                  onClick={onLogout}
                  className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-600 hover:bg-red-50 transition-colors"
                >
                  <LogOut className="h-4 w-4" /> Sign Out
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  )
}
