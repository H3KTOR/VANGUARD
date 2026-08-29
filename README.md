این متن readme.md گیتهابم رو مرتب کن و دستورات راحتتر قابل کپی بشن

VANGUARD v3.0 🛡️

Enterprise-Grade, Edge-Native Linux IDS/IPS & Security Operations Platform
VANGUARD is a comprehensive, low-footprint Intrusion 
Detection and Prevention System (IDS/IPS) engineered specifically for 
standalone Linux servers. It merges deterministic attack detection, 
automated firewall mitigation, and an embedded React dashboard into a 
single ~25MB zero-dependency static binary.
Coupled with an ephemeral Python toolkit for AI-driven 
forensics and OSINT synchronization, VANGUARD delivers a complete 
Security Operations Center (SOC) experience that operates entirely on 
the edge, without requiring external cloud databases or third-party web 
servers.

🧠 Design Philosophy & Architecture
VANGUARD is built on three core principles: Zero External Dependencies, Fail-Safe Mitigation, and Strict Separation of Concerns.

The Polyglot Stack
The Core Daemon (Go):
A high-performance, concurrent engine that handles log tailing (auth.log, Nginx/Apache), dynamic risk scoring, and OS-level firewall execution (ufw/iptables). It embeds a lightweight Echo REST API and serves the compiled React dashboard directly from memory using //go:embed.
The Data Layer (SQLite in WAL Mode):
Uses the pure-Go glebarez/sqlite driver (CGO-free). The database is strictly configured with PRAGMA journal_mode=WAL and busy_timeout to ensure the always-on Go daemon never blocks the ephemeral Python toolkit from reading data.
The Embedded SOC (React + Vite):
A responsive, client-side dashboard featuring modular architecture, custom polling hooks for live data, and manualChunks code-splitting for sub-second load times.
The Ephemeral Toolkit (Python 3):
A cron-triggered CLI tool utilizing Typer. It consumes 0 RAM when idle. It strictly connects to SQLite in mode=ro (Read-Only) for AI analysis and reporting, ensuring it can never corrupt the Go daemon's WAL state.
✨ Core Capabilities
🔍 Deterministic Detection & Risk Scoring
VANGUARD shuns noisy heuristic ML models in favor of a 
deterministic rule engine with sliding-window state management (lazy 
pruning).

SSH Brute Force & Escalation: Detects high-frequency failures and flags CRITICAL escalation if a successful login immediately follows a brute-force sequence.
Web Threat Detection: Identifies Directory Scanning, Path Traversal (../../), SQLi/XSS probing, and HTTP Floods.
Deception Layer (Honeypot): Built-in decoy 
listeners (e.g., fake SSH on port 2222, fake MySQL). Any TCP connection 
to a decoy instantly triggers a zero-threshold CRITICAL response.
🛡️ Autopilot & Action Engine
Converts detection events into immediate OS-level firewall rules while prioritizing operator safety.

Fail-Safe Whitelisting: A hardcoded AdminWhitelistIPs configuration guarantees that the Autopilot will never lock out system administrators, regardless of risk scores.
TTL Ban Reaper: Automated block lifecycle management. Bans expire naturally and are reaped by a background goroutine.
Panic Mode (System Lockdown): A site-wide emergency kill-switch. It defaults to a Mandatory Dry-Run Preview
 (showing exactly which connections will drop) and requires explicit 
two-step confirmation. Includes an automatic 30-minute rollback to 
prevent permanent self-lockout.
🤖 AI Forensics & OSINT Synchronization
LLM Analyst: Integrates securely with Anthropic (Claude) and OpenAI. Generates structured JSON verdicts detailing Likely Intent, Threat Actor Sophistication, and MITRE ATT&CK mappings. Features graceful degradation on API failures.
OSINT Threat Feed: Synchronizes with public blocklists (e.g., ipsum), filtering out internal/loopback IPs automatically before staging bulk firewall bans in a single short-lived transaction.
🛠️ Installation & Deployment
VANGUARD is designed to be deployed as a systemd service running under a dedicated, unprivileged Linux user.

1. Build from Source
Clone the repository
git clone https://github.com/H3KTOR/VANGUARD.git
cd VANGUARD

Build the React frontend AND embed it into the compiled Go binary
make build

2. Production Setup (systemd)
Move the binary to your executable path and configure the environment:
sudo cp core/vanguard /usr/local/bin/
sudo useradd -r -s /bin/false vanguard
sudo mkdir -p /var/lib/vanguard && sudo chown vanguard:vanguard /var/lib/vanguard

Create the secure environment file
sudo nano /etc/vanguard.env

Add: VANGUARD_JWT_SECRET=your_super_secure_random_string
Install the provided systemd service:
sudo cp docs/vanguard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vanguard

3. Toolkit Setup (Cron)
cd /opt/vanguard-toolkit
pip3 install -r requirements.txt

Add to crontab (crontab -e)
Run OSINT sync nightly at 2 AM
0 2 * * * cd /opt/vanguard-toolkit && python3 main.py sync >> /var/log/vanguard-sync.log 2>&1

💻 Development & Attack Simulation
VANGUARD ships with a built-in simulator package to generate realistic synthetic incidents and bans safely without touching the host OS firewall.

Start the daemon in development mode
./core/vanguard serve -db vanguard-dev.db -honeypot=false

In another terminal, simulate a targeted SSH brute-force attack
./core/vanguard simulate ssh-bruteforce -db vanguard-dev.db -ip 198.51.100.23 -attempts 45

Trigger the decoy honeypot
./core/vanguard simulate honeypot -db vanguard-dev.db
For frontend development, VANGUARD proxies API requests to the Go backend, supporting Vite's Hot Module Replacement (HMR):
cd core/frontend
npm install
npm run dev

🧪 Testing & QA
VANGUARD maintains strict quality assurance across all three languages. Run the test suites locally:

Go Core (Unit & Integration):
cd core && go test ./...

React Dashboard (Vitest + React Testing Library):
Includes robust mocks for vanguardClient.js and ResizeObserver.
cd core/frontend && npx vitest run

20/20 tests passing
Python Toolkit (Pytest):
Full mock coverage using unittest.mock and responses to ensure zero real network/DB calls during CI/CD.
cd toolkit && pytest -q

55/55 tests passing
📂 Codebase Structure
VANGUARD/
├── core/
│   ├── cmd/vanguard/        # Daemon entry point & embedded FS routing (mountFrontend)
│   ├── frontend/            # React SPA (Vite, Tailwind, Recharts, Lucide)
│   └── internal/
│       ├── api/             # Echo REST API & JWT Auth Middleware
│       ├── database/        # SQLite GORM Models & WAL Configuration
│       ├── detection/       # Rule Engine, Log Tailers, Sliding-Window State
│       ├── firewall/        # UFW/iptables Execution, Autopilot, Panic Mode
│       └── simulator/       # Synthetic Attack Generator
├── toolkit/                 # Python CLI (AI Analyst, OSINT Sync, PDF Reports)
└── docs/                    # Architecture diagrams & systemd configurations
Architected and developed by Masoud Hosseinpour.
