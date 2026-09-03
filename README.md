# VANGUARD v3.0 🛡️

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go)
![React](https://img.shields.io/badge/React-18%2B-61DAFB?logo=react)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python)

> **Enterprise-grade, edge-native Linux IDS/IPS & Security Operations Platform**

VANGUARD is a comprehensive, low-footprint **Intrusion Detection and Prevention System (IDS/IPS)** engineered specifically for standalone Linux servers.

It combines:

* 🔍 Deterministic threat detection
* 📊 Dynamic risk scoring
* 🛡️ Automated firewall mitigation
* 🖥️ Embedded React SOC dashboard
* 🤖 AI-assisted forensic analysis
* 🌐 OSINT threat intelligence synchronization
* 🍯 Honeypot-based deception
* 🚨 Emergency system lockdown capabilities

All within a single **~25 MB zero-dependency static binary**.

VANGUARD provides a complete **edge-native Security Operations Center (SOC)** experience without requiring external cloud databases or third-party web servers.

---

## 📑 Table of Contents

* [Architecture](#-architecture)
* [Core Capabilities](#-core-capabilities)
* [Detection Engine](#-detection-engine)
* [Autopilot & Action Engine](#️-autopilot--action-engine)
* [Honeypot & Deception](#-honeypot--deception)
* [Performance](#-performance--stress-testing)
* [AI Forensics](#-ai-forensics)
* [OSINT Threat Intelligence](#-osint-threat-intelligence)
* [Installation](#️-installation--deployment)
* [Development](#-development--attack-simulation)
* [Frontend Development](#-frontend-development)
* [Testing](#-testing--quality-assurance)
* [Project Structure](#-project-structure)
* [Security Model](#-security-model)
* [Technology Stack](#️-technology-stack)
* [Project Status](#-project-status)
* [Author](#-author)

---

# 🧠 Architecture

VANGUARD is built around three core architectural principles:

> **Zero External Dependencies · Fail-Safe Mitigation · Strict Separation of Concerns**

The platform uses a polyglot architecture in which each component has a clearly defined responsibility.

```text
┌─────────────────────────────────────────────────────────────┐
│                        Linux Server                         │
│                                                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │                 VANGUARD Core — Go                  │  │
│  │                                                       │  │
│  │  Detection │ Risk Engine │ Firewall │ REST API       │  │
│  │  Log Tailing │ Honeypot │ Simulator │ Scheduler      │  │
│  └───────────────────────┬───────────────────────────────┘  │
│                          │                                  │
│                    ┌─────▼─────┐                            │
│                    │  SQLite   │                            │
│                    │    WAL    │                            │
│                    └─────┬─────┘                            │
│                          │                                  │
│             ┌────────────┴────────────┐                     │
│             │                         │                     │
│      ┌──────▼──────┐           ┌──────▼──────┐              │
│      │   React     │           │   Python    │              │
│      │     SOC     │           │   Toolkit   │              │
│      │  Dashboard  │           │ AI + OSINT  │              │
│      └─────────────┘           └──────┬──────┘              │
│                                      │                     │
└──────────────────────────────────────┼─────────────────────┘
                                       │
                         ┌─────────────┴─────────────┐
                         │                           │
                   ┌─────▼─────┐               ┌─────▼─────┐
                   │ AI Analyst│               │ OSINT Feed│
                   │           │               │ Sources   │
                   └───────────┘               └───────────┘
```

---

## 🐹 Core Engine — Go

The Go daemon is the primary VANGUARD runtime.

It is responsible for:

* Linux authentication and web log monitoring
* Deterministic threat detection
* Sliding-window state management
* Dynamic risk scoring
* Firewall enforcement
* Honeypot listeners
* REST API
* JWT authentication
* Attack simulation
* Background ban expiration
* Embedded frontend delivery

Supported firewall integrations include:

```text
UFW
iptables
```

The compiled React application is embedded directly into the Go binary using Go's `//go:embed` functionality.

---

## 🗄️ Data Layer — SQLite

VANGUARD uses SQLite in **WAL (Write-Ahead Logging)** mode with the pure-Go `glebarez/sqlite` driver.

Key configuration:

```sql
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
```

This allows the always-on Go daemon and the ephemeral Python toolkit to interact with the database without unnecessary blocking.

The Python toolkit connects to SQLite in:

```text
mode=ro
```

This ensures that the toolkit operates in **read-only mode** and cannot modify the daemon's database state.

---

## ⚛️ Embedded SOC — React + Vite

VANGUARD includes a responsive security operations dashboard built with React.

The dashboard provides:

* Real-time security telemetry
* Threat visualization
* Security event monitoring
* Live polling hooks
* Modular React architecture
* Code splitting with Vite `manualChunks`
* Responsive UI
* Sub-second dashboard loading

The production frontend is compiled and embedded directly into the Go binary.

---

## 🐍 Ephemeral Toolkit — Python

The Python toolkit is a lightweight, cron-triggered CLI environment built with **Typer**.

It is designed to remain inactive when no scheduled task is executing.

The toolkit performs:

* AI-assisted forensic analysis
* OSINT threat intelligence synchronization
* Security report generation
* Database read-only analysis
* Automated intelligence workflows

The toolkit **never modifies the VANGUARD daemon database**.

---

# ✨ Core Capabilities

## 🔍 Deterministic Detection & Risk Scoring

Rather than relying on noisy machine-learning models for primary detection, VANGUARD uses a deterministic rule engine with:

* Sliding-window state management
* Lazy state pruning
* Event correlation
* Risk scoring
* Escalation detection

This makes the primary detection layer predictable, explainable, and suitable for security automation.

---

## 🔐 SSH Brute-Force Detection

VANGUARD detects:

* High-frequency authentication failures
* Repeated login attempts
* Suspicious authentication patterns
* Successful logins immediately following brute-force activity

The system can correlate authentication events rather than treating every log entry as an isolated event.

---

## 🌐 Web Threat Detection

VANGUARD analyzes web server logs for common attack patterns, including:

* Directory scanning
* Path traversal
* SQL injection probing
* XSS probing
* HTTP flooding

Example path traversal pattern:

```text
../../
```

### Architecture Note

VANGUARD operates as an **out-of-band IDS**, rather than an inline Web Application Firewall (WAF).

Layer 7 HTTP flood mitigation therefore requires integration with front-end reverse-proxy or web-server logs using:

```text
-web-log
```

---

# 🍯 Honeypot & Deception

VANGUARD includes configurable decoy listeners designed to identify unsolicited access attempts.

Example decoy services include:

```text
Fake SSH     → 2222
Fake MySQL
Other configurable services
```

Any TCP connection to a configured decoy service immediately generates a:

```text
CRITICAL
```

security event.

This provides an additional detection layer for attackers performing reconnaissance or service discovery.

---

# 🛡️ Autopilot & Action Engine

VANGUARD converts security events into automated OS-level mitigation actions while prioritizing operator safety.

The action engine includes:

* Automatic IP banning
* TTL-based ban expiration
* Firewall integration
* Administrative IP whitelisting
* Emergency lockdown
* Background ban cleanup

---

## 🟢 Fail-Safe Whitelisting

VANGUARD maintains an administrative whitelist:

```text
AdminWhitelistIPs
```

Trusted administrator IP addresses are protected from automated lockouts regardless of their calculated risk score.

This provides a critical safety layer for autonomous firewall enforcement.

---

## ⏱️ TTL Ban Reaper

Firewall bans are not intended to persist indefinitely.

VANGUARD maintains ban expiration metadata and uses a background goroutine to automatically remove expired bans.

```text
Threat detected
      │
      ▼
Risk evaluation
      │
      ▼
Firewall ban
      │
      ▼
TTL countdown
      │
      ▼
Automatic removal
```

---

# 🚨 Panic Mode

Panic Mode provides a site-wide emergency firewall lockdown.

The workflow is intentionally designed to reduce accidental self-lockout.

### Panic Mode includes:

1. Mandatory dry-run preview
2. Exact preview of connections that will be dropped
3. Explicit two-step confirmation
4. Automatic 30-minute rollback

The automatic rollback ensures that an emergency lockdown does not permanently isolate the administrator from the server.

### Firewall Privileges

Full firewall enforcement requires the VANGUARD daemon to have appropriate network-control privileges.

For example:

```bash
sudo ./core/vanguard serve -ufw
```

This allows VANGUARD to integrate with the host's OS-level firewall and enforce mitigation at the kernel layer.

---

# 📈 Performance & Stress Testing

VANGUARD has been stress-tested against simulated:

* Layer 4 SYN floods using `hping3`
* Layer 7 HTTP floods using `wrk`

The objective was to evaluate detection performance, memory behavior, CPU utilization, and administrative accessibility under heavy load.

---

## High-Concurrency Handling

During HTTP flood benchmarking:

```text
Concurrent connections: 1,000
Requests:                178,000+ per minute
```

VANGUARD successfully managed the peak application load while maintaining administrative dashboard accessibility.

---

## Memory Efficiency

Profiling during high-load testing showed:

```text
Idle RSS:       ~21 MB
Peak RSS:       ~68 MB
Additional RAM: ~46 MB
```

Memory consumption remained bounded during the stress test, with no observed persistent memory growth after the attack subsided.

---

## CPU Utilization

During peak flood conditions, the VANGUARD application process reached approximately:

```text
~9% CPU
```

The host's networking stack may experience significantly higher utilization while handling large volumes of TCP traffic, but the VANGUARD application itself remains lightweight.

---

## Elastic Recovery

After attack traffic stopped or firewall mitigation was applied:

```text
CPU → baseline
Memory → baseline
Dashboard → responsive
Processes → clean
```

The system demonstrated rapid recovery without persistent application degradation.

---

# 🤖 AI Forensics

VANGUARD integrates external LLM providers for post-detection forensic analysis.

Supported providers include:

* Anthropic Claude
* OpenAI

The AI analyst produces structured JSON verdicts.

Example:

```json
{
  "likely_intent": "...",
  "threat_actor_sophistication": "...",
  "mitre_attack_mapping": []
}
```

Potential analytical outputs include:

* Likely attacker intent
* Threat actor sophistication
* MITRE ATT&CK mappings
* Incident interpretation
* Forensic context

### Graceful Degradation

AI analysis is an auxiliary capability rather than a hard dependency.

If an external AI API is unavailable, the core detection and mitigation pipeline can continue operating independently.

---

# 🌐 OSINT Threat Intelligence

The Python toolkit synchronizes VANGUARD with public threat-intelligence sources, including blocklists such as **ipsum**.

The synchronization process:

```text
Fetch threat intelligence
          │
          ▼
Filter invalid/internal IPs
          │
          ▼
Stage malicious addresses
          │
          ▼
Bulk firewall enforcement
          │
          ▼
Complete transaction
```

The synchronization layer automatically:

* Filters internal IP addresses
* Filters loopback addresses
* Stages malicious IP addresses
* Performs bulk firewall bans
* Uses short-lived database transactions

---

# 🛠️ Installation & Deployment

VANGUARD is designed for Linux production environments and can operate as a `systemd` service under a dedicated unprivileged user.

## Requirements

Recommended environment:

```text
Linux
Go 1.21+
Node.js / npm
Python 3.10+
SQLite
systemd
UFW or iptables
```

---

## 1. Build from Source

Clone the repository:

```bash
git clone https://github.com/H3KTOR/VANGUARD.git
cd VANGUARD
```

Build the frontend and compile the Go application:

```bash
make build
```

The production frontend is embedded into the resulting Go binary.

---

# 2. Production systemd Setup

## Install the binary

```bash
sudo cp core/vanguard /usr/local/bin/
```

## Create a dedicated system user

```bash
sudo useradd -r -s /bin/false vanguard
```

## Create the application data directory

```bash
sudo mkdir -p /var/lib/vanguard
sudo chown vanguard:vanguard /var/lib/vanguard
```

## Create the environment file

```bash
sudo nano /etc/vanguard.env
```

Add your JWT secret:

```env
VANGUARD_JWT_SECRET=your_super_secure_random_string
```

## Install the systemd service

```bash
sudo cp docs/vanguard.service /etc/systemd/system/
```

## Reload systemd

```bash
sudo systemctl daemon-reload
```

## Enable and start VANGUARD

```bash
sudo systemctl enable --now vanguard
```

## Check service status

```bash
sudo systemctl status vanguard
```

---

# 3. Python Toolkit Setup

Navigate to the toolkit:

```bash
cd /opt/vanguard-toolkit
```

Install dependencies:

```bash
pip3 install -r requirements.txt
```

---

## Configure Cron

Open the crontab:

```bash
crontab -e
```

Run OSINT synchronization every night at **02:00**:

```cron
0 2 * * * cd /opt/vanguard-toolkit && python3 main.py sync >> /var/log/vanguard-sync.log 2>&1
```

---

# 🧪 Development & Attack Simulation

VANGUARD includes a built-in attack simulator capable of generating realistic synthetic incidents and bans **without modifying the host OS firewall**.

This makes it possible to test detection and dashboard behavior safely during development.

---

## Start the Development Daemon

```bash
./core/vanguard serve \
  -db vanguard-dev.db \
  -honeypot=false
```

---

## Simulate SSH Brute Force

In another terminal:

```bash
./core/vanguard simulate ssh-bruteforce \
  -db vanguard-dev.db \
  -ip 198.51.100.23 \
  -attempts 45
```

The simulator generates a realistic SSH brute-force sequence against the selected test IP.

---

## Trigger the Honeypot

```bash
./core/vanguard simulate honeypot \
  -db vanguard-dev.db
```

---

# 🎨 Frontend Development

During development, VANGUARD proxies API requests to the Go backend while supporting Vite Hot Module Replacement (HMR).

Navigate to the frontend:

```bash
cd core/frontend
```

Install dependencies:

```bash
npm install
```

Start the development server:

```bash
npm run dev
```

---

# 🧪 Testing & Quality Assurance

VANGUARD maintains automated testing across its Go, React, and Python components.

---

## 🐹 Go Core

Run Go unit and integration tests:

```bash
cd core
go test ./...
```

---

## ⚛️ React Dashboard

The frontend test suite uses:

* Vitest
* React Testing Library
* Mocked `vanguardClient.js`
* `ResizeObserver` mocks

Run:

```bash
cd core/frontend
npx vitest run
```

Current result:

```text
20/20 tests passing
```

---

## 🐍 Python Toolkit

The Python toolkit uses:

* Pytest
* `unittest.mock`
* `responses`

The test suite is designed to ensure CI/CD tests perform:

```text
Zero real network operations
Zero real database operations
```

Run:

```bash
cd toolkit
pytest -q
```

Current result:

```text
55/55 tests passing
```

---

# 📂 Project Structure

```text
VANGUARD/
│
├── core/
│   ├── cmd/
│   │   └── vanguard/
│   │       └── # Daemon entry point & embedded FS routing
│   │
│   ├── frontend/
│   │   └── # React SPA
│   │       ├── Vite
│   │       ├── Tailwind
│   │       ├── Recharts
│   │       └── Lucide
│   │
│   └── internal/
│       ├── api/
│       │   └── # Echo REST API & JWT authentication
│       │
│       ├── database/
│       │   └── # SQLite GORM models & WAL configuration
│       │
│       ├── detection/
│       │   └── # Rule engine, log tailers & sliding-window state
│       │
│       ├── firewall/
│       │   └── # UFW/iptables, Autopilot & Panic Mode
│       │
│       └── simulator/
│           └── # Synthetic attack generator
│
├── toolkit/
│   └── # Python CLI
│       ├── AI Analyst
│       ├── OSINT Sync
│       └── PDF Reports
│
└── docs/
    └── # Architecture diagrams & systemd configurations
```

---

# 🏗️ Runtime Architecture

```text
                         ┌──────────────────────────┐
                         │       Linux Server       │
                         │                          │
                         │  ┌────────────────────┐  │
                         │  │   VANGUARD Core    │  │
                         │  │        Go          │  │
                         │  └─────────┬──────────┘  │
                         │            │             │
                         │     ┌──────▼──────┐      │
                         │     │    SQLite    │      │
                         │     │     WAL      │      │
                         │     └──────┬──────┘      │
                         │            │             │
                         │     ┌──────▼──────┐      │
                         │     │   Python     │      │
                         │     │   Toolkit    │      │
                         │     └──────┬──────┘      │
                         │            │             │
                         └────────────┼─────────────┘
                                      │
                         ┌────────────┴────────────┐
                         │                         │
                   ┌─────▼─────┐             ┌─────▼─────┐
                   │    AI     │             │   OSINT   │
                   │  Analyst  │             │   Feeds   │
                   └───────────┘             └───────────┘
```

---

# 🔐 Security Model

VANGUARD follows a defense-in-depth architecture:

```text
                 ┌─────────────────────┐
                 │   Incoming Traffic  │
                 └──────────┬──────────┘
                            │
                 ┌──────────▼──────────┐
                 │  Log / Event Input  │
                 └──────────┬──────────┘
                            │
                 ┌──────────▼──────────┐
                 │ Deterministic Rules │
                 └──────────┬──────────┘
                            │
                 ┌──────────▼──────────┐
                 │    Risk Scoring     │
                 └──────────┬──────────┘
                            │
              ┌─────────────┴─────────────┐
              │                           │
        ┌─────▼─────┐               ┌─────▼─────┐
        │  Monitor  │               │ Autopilot │
        └───────────┘               └─────┬─────┘
                                          │
                                   ┌──────▼──────┐
                                   │  Firewall   │
                                   │ Mitigation  │
                                   └─────────────┘
```

The architecture separates:

```text
Detection
   ↓
Risk Assessment
   ↓
Operator Monitoring
   ↓
Automated Mitigation
```

This separation allows VANGUARD to remain useful as a monitoring platform while also supporting autonomous response.

---

# ⚙️ Technology Stack

| Component       | Technology                |
| --------------- | ------------------------- |
| Core Engine     | Go                        |
| REST API        | Echo                      |
| Database        | SQLite                    |
| SQLite Driver   | glebarez/sqlite           |
| Frontend        | React                     |
| Frontend Build  | Vite                      |
| Styling         | Tailwind CSS              |
| Charts          | Recharts                  |
| Icons           | Lucide                    |
| AI Analysis     | Anthropic / OpenAI        |
| Toolkit         | Python 3 + Typer          |
| Service Manager | systemd                   |
| Firewall        | UFW / iptables            |
| Detection       | Deterministic Rule Engine |
| Database Mode   | WAL                       |
| Deployment      | Static Linux Binary       |

---

# 📊 Project Highlights

| Capability           | Implementation                        |
| -------------------- | ------------------------------------- |
| SSH Detection        | Deterministic authentication analysis |
| Web Threat Detection | Log-based attack pattern detection    |
| Risk Engine          | Dynamic risk scoring                  |
| Firewall Automation  | UFW / iptables                        |
| Ban Management       | TTL-based expiration                  |
| Emergency Response   | Panic Mode + rollback                 |
| Deception            | Configurable honeypot listeners       |
| SOC Dashboard        | Embedded React application            |
| AI Investigation     | Anthropic / OpenAI                    |
| Threat Intelligence  | OSINT blocklist synchronization       |
| Database             | SQLite WAL                            |
| Runtime              | Edge-native Go daemon                 |
| Deployment           | Single static binary                  |
| Testing              | Go + Vitest + Pytest                  |

---

# 🚀 Project Status

**VANGUARD v3.0** is an actively developed security platform combining:

* Deterministic threat detection
* Automated firewall mitigation
* AI-assisted investigation
* OSINT threat intelligence
* Honeypot-based deception
* Embedded SOC visualization
* Edge-native deployment

The project is designed around the principle that a security platform should remain **lightweight, autonomous, explainable, and resilient** without requiring a large external infrastructure footprint.

---

# 👨‍💻 Author

**Architected and developed by Masoud Hosseinpour.**

---

# ⭐ Support the Project

If VANGUARD is useful or interesting to you:

```text
⭐ Star the repository
🍴 Fork the project
🐛 Report issues
💡 Suggest improvements
```

---

<div align="center">

### VANGUARD v3.0

**Security at the Edge.**

</div>
