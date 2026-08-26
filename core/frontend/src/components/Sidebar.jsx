import {
  LayoutDashboard,
  ShieldAlert,
  Flame,
  Radio,
  LineChart,
  Settings,
  ShieldCheck,
  Circle,
} from 'lucide-react'

// Sidebar: fixed left navigation matching the reference layout --
// a compact brand header, two grouped nav sections (OPERATIONS /
// PLATFORM), and a persistent node-status footer showing the daemon is
// alive (derived from the /api/health poll owned by App.jsx).
const OPERATIONS_ITEMS = [
  { id: 'command-center', label: 'Command Center', icon: LayoutDashboard },
  { id: 'incidents', label: 'Incidents', icon: ShieldAlert },
  { id: 'firewall', label: 'Firewall Rules', icon: Flame },
  { id: 'honeypot', label: 'Honeypot', icon: Radio },
]

const PLATFORM_ITEMS = [
  { id: 'metrics', label: 'System Metrics', icon: LineChart },
  { id: 'settings', label: 'Settings', icon: Settings },
]

function NavGroup({ title, items, active, onSelect }) {
  return (
    <div className="mb-6">
      <p className="px-3 mb-2 text-[10px] font-bold tracking-widest text-slate-400 uppercase">{title}</p>
      <div className="space-y-0.5">
        {items.map((item) => {
          const Icon = item.icon
          const isActive = active === item.id
          return (
            <button
              key={item.id}
              onClick={() => onSelect(item.id)}
              className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-slate-900 text-white shadow-sm'
                  : 'text-slate-600 hover:bg-slate-100 hover:text-slate-900'
              }`}
            >
              <Icon className="h-4 w-4 flex-shrink-0" strokeWidth={2} />
              <span className="truncate">{item.label}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

export default function Sidebar({ active, onSelect, nodeOnline, uptimeLabel }) {
  return (
    <aside className="hidden lg:flex lg:flex-col w-64 flex-shrink-0 h-screen sticky top-0 border-r border-slate-200 bg-white">
      <div className="flex items-center gap-2.5 px-5 h-16 border-b border-slate-200 flex-shrink-0">
        <div className="h-8 w-8 rounded-lg bg-slate-900 flex items-center justify-center">
          <ShieldCheck className="h-4.5 w-4.5 text-white" strokeWidth={2.5} />
        </div>
        <div className="leading-tight">
          <p className="text-sm font-extrabold text-slate-900 tracking-tight">VANGUARD</p>
          <p className="text-[10px] text-slate-400 font-medium">v3.0 SOC Platform</p>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto px-3 py-5">
        <NavGroup title="Operations" items={OPERATIONS_ITEMS} active={active} onSelect={onSelect} />
        <NavGroup title="Platform" items={PLATFORM_ITEMS} active={active} onSelect={onSelect} />
      </nav>

      <div className="p-3 border-t border-slate-200 flex-shrink-0">
        <div className="rounded-xl bg-slate-50 border border-slate-200 px-3 py-2.5">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              {nodeOnline && (
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
              )}
              <span
                className={`relative inline-flex rounded-full h-2 w-2 ${
                  nodeOnline ? 'bg-green-500' : 'bg-red-500'
                }`}
              />
            </span>
            <span className="text-xs font-semibold text-slate-700">vanguard-core-01</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1 pl-4">
            {nodeOnline ? `Online \u00b7 up ${uptimeLabel}` : 'Unreachable'}
          </p>
        </div>
      </div>
    </aside>
  )
}
