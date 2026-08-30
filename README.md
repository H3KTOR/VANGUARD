# VANGUARD v3.0 🛡️[cite: 1]

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)[cite: 1]
![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)[cite: 1]
![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go)[cite: 1]
![React Version](https://img.shields.io/badge/React-18.0+-61DAFB?logo=react)[cite: 1]
![Python Version](https://img.shields.io/badge/Python-3.10+-3776AB?logo=python)[cite: 1]
### Enterprise-Grade, Edge-Native Linux IDS/IPS & Security Operations Platform[cite: 1]

**VANGUARD** is a comprehensive, low-footprint **Intrusion Detection and Prevention System (IDS/IPS)** engineered specifically for standalone Linux servers.[cite: 1]

It combines:[cite: 1]

- Deterministic attack detection[cite: 1]
- Dynamic risk scoring[cite: 1]
- Automated firewall mitigation[cite: 1]
- Embedded React security dashboard[cite: 1]
- AI-powered forensic analysis[cite: 1]
- OSINT threat intelligence synchronization[cite: 1]

All within a single **~25 MB zero-dependency static binary**.[cite: 1]

VANGUARD delivers a complete **Security Operations Center (SOC)** experience that runs entirely on the edge, without requiring external cloud databases or third-party web servers.[cite: 1]

---[cite: 1]

# 🧠 Design Philosophy & Architecture[cite: 1]

VANGUARD is built around three core principles:[cite: 1]

> **Zero External Dependencies · Fail-Safe Mitigation · Strict Separation of Concerns**[cite: 1]

## The Polyglot Stack[cite: 1]

### 🐹 Core Daemon — Go[cite: 1]

A high-performance concurrent engine responsible for:[cite: 1]

- Log tailing (`auth.log`, Nginx, Apache)[cite: 1]
- Dynamic risk scoring[cite: 1]
- Deterministic threat detection[cite: 1]
- OS-level firewall execution (`ufw` / `iptables`)[cite: 1]
- REST API powered by Echo[cite: 1]
- Embedded frontend serving via `//go:embed`[cite: 1]

The compiled React dashboard is served directly from the Go binary.[cite: 1]

---[cite: 1]

### 🗄️ Data Layer — SQLite[cite: 1]

VANGUARD uses SQLite in **WAL (Write-Ahead Logging) mode** with the pure-Go `glebarez/sqlite` driver.[cite: 1]

Key configuration:[cite: 1]

```sql
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;

```

This allows the always-on Go daemon and the ephemeral Python toolkit to access the database safely without blocking each other.

The Python toolkit connects using:

```text
mode=ro

```

ensuring that it can only read data and cannot modify or corrupt the daemon's database state.

---

### ⚛️ Embedded SOC — React + Vite



A responsive client-side security dashboard featuring:

* Modular React architecture


* Live polling hooks


* Real-time telemetry


* Threat visualization


* ManualChunks code splitting


* Sub-second dashboard loading



The compiled frontend is embedded directly into the Go binary.

---

### 🐍 Ephemeral Toolkit — Python 3



A lightweight cron-triggered CLI toolkit built with **Typer**.

It is designed to remain completely inactive when not executing a scheduled task.

The toolkit:

* Performs AI-assisted forensic analysis


* Synchronizes OSINT threat intelligence


* Generates security reports


* Reads SQLite in **read-only mode**

* Never modifies the Go daemon's database



---

# ✨ Core Capabilities



## 🔍 Deterministic Detection & Risk Scoring



Instead of relying on noisy heuristic ML models for primary detection, VANGUARD uses a deterministic rule engine with **sliding-window state management** and lazy pruning.

### 🔐 SSH Brute Force & Escalation



Detects high-frequency authentication failures and identifies suspicious successful logins immediately following brute-force activity.

### 🌐 Web Threat Detection



Detects common web-based attack patterns, including:

* Directory scanning


* Path traversal (`../../`)


* SQL Injection probing


* XSS probing


* HTTP flooding



> **Architecture Note:** VANGUARD operates as an out-of-band IDS rather than an inline WAF. Mitigating Layer 7 HTTP floods requires integrating the daemon with front-end reverse proxy logs using the `-web-log` flag.

### 🍯 Deception Layer — Honeypot



Built-in decoy listeners can expose fake services such as:

* Fake SSH — `2222`

* Fake MySQL


* Other configurable decoy services



Any TCP connection to a decoy service immediately triggers a **CRITICAL** security event.

---

# 🛡️ Autopilot & Action Engine



VANGUARD converts detection events into immediate OS-level firewall actions while prioritizing operator safety.

### 🟢 Fail-Safe Whitelisting



A hardcoded:

```text
AdminWhitelistIPs

```

configuration ensures that Autopilot will never lock out trusted system administrators regardless of the calculated risk score.

### ⏱️ TTL Ban Reaper



Automated firewall-ban lifecycle management.

Bans automatically expire and are reaped by a background goroutine.

### 🚨 Panic Mode — System Lockdown



A site-wide emergency firewall kill-switch.

Panic Mode includes:

1. Mandatory dry-run preview


2. Exact preview of connections that will be dropped


3. Explicit two-step confirmation


4. Automatic 30-minute rollback



The automatic rollback is designed to prevent permanent self-lockout.

> **Security Note:** Full enforcement requires the daemon to be initialized with root-level network control (e.g., `sudo ./core/vanguard serve -ufw`) to seamlessly integrate with the host's OS-level firewall and drop traffic at the kernel layer.

---

# 📈 Performance Benchmarks & Stress Testing

VANGUARD has been rigorously stress-tested against severe Layer 4 (`hping3` SYN floods) and Layer 7 (`wrk` HTTP floods) attack simulations to ensure edge-native resilience.

### High Concurrency Handling

Under heavy HTTP flood benchmarking (1,000 concurrent connections generating over 178,000 requests per minute), the system successfully managed the peak load queue without dropping administrative dashboard access.

### Process-Level Resource Efficiency

Granular profiling during stress testing reveals exceptional backend optimization:

* **Ultra-Low Memory Footprint:** The VANGUARD daemon scales from an idle baseline of **~21 MB (RSS)** to a peak of strictly **~68 MB** under extreme stress (requiring only ~46 MB of additional RAM to manage 1,000 concurrent connections).
* **Zero Memory Leaks:** Despite massive request influxes, memory consumption remains strictly bounded. The flatline in RAM usage during and after high-stress events demonstrates perfect garbage collection.
* **Optimized CPU Utilization:** During peak floods, the VANGUARD application process consumes a maximum of **~9% CPU**. While the host OS network stack may reach 100% capacity handling the TCP queue, the Go backend remains lightweight and highly responsive.

### Elastic Recovery

Immediately upon attack cessation or UFW ban execution, the system instantly recovers to baseline idle states (0% CPU). The core engine exhibits rapid recovery with zero lingering ghost processes or service degradation.

---

# 🤖 AI Forensics & OSINT Synchronization



## 🧠 LLM Analyst



VANGUARD integrates with:

* Anthropic Claude


* OpenAI



The LLM analyst produces structured JSON verdicts containing information such as:

```json
{
  "likely_intent": "...",
  "threat_actor_sophistication": "...",
  "mitre_attack_mapping": []
}

```

The system also provides graceful degradation when an external AI API is unavailable.

---

## 🌐 OSINT Threat Feed



VANGUARD synchronizes with public threat intelligence blocklists, including sources such as **ipsum**.

The synchronization layer automatically:

* Filters internal IP addresses


* Filters loopback addresses


* Stages malicious IPs


* Performs bulk firewall bans


* Uses a short-lived database transaction



---

# 🛠️ Installation & Deployment



VANGUARD is designed to run as a **systemd service** under a dedicated unprivileged Linux user.

## 1. Build from Source



### Clone the repository



```bash
git clone https://github.com/H3KTOR/VANGUARD.git
cd VANGUARD

```

### Build the frontend and embed it into the Go binary



```bash
make build

```

---

# 2. Production Setup — systemd



### Install the binary



```bash
sudo cp core/vanguard /usr/local/bin/

```

### Create a dedicated system user



```bash
sudo useradd -r -s /bin/false vanguard

```

### Create the application data directory



```bash
sudo mkdir -p /var/lib/vanguard
sudo chown vanguard:vanguard /var/lib/vanguard

```

### Create the secure environment file



```bash
sudo nano /etc/vanguard.env

```

Add your JWT secret:

```env
VANGUARD_JWT_SECRET=your_super_secure_random_string

```

### Install the systemd service



```bash
sudo cp docs/vanguard.service /etc/systemd/system/

```

### Reload systemd



```bash
sudo systemctl daemon-reload

```

### Enable and start VANGUARD



```bash
sudo systemctl enable --now vanguard

```

### Check service status



```bash
sudo systemctl status vanguard

```

---

# 3. Python Toolkit Setup



Navigate to the toolkit directory:

```bash
cd /opt/vanguard-toolkit

```

Install dependencies:

```bash
pip3 install -r requirements.txt

```

### Configure Cron



Open the crontab:

```bash
crontab -e

```

Run the OSINT synchronization every night at **02:00**:

```cron
0 2 * * * cd /opt/vanguard-toolkit && python3 main.py sync >> /var/log/vanguard-sync.log 2>&1

```

---

# 💻 Development & Attack Simulation



VANGUARD includes a built-in simulator capable of generating realistic synthetic incidents and bans **without modifying the host OS firewall**.

## Start the daemon in development mode



```bash
./core/vanguard serve -db vanguard-dev.db -honeypot=false

```

---

## Simulate an SSH Brute-Force Attack



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



VANGUARD proxies API requests to the Go backend while supporting **Vite Hot Module Replacement (HMR)**.

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

# 🧪 Testing & QA



VANGUARD maintains automated quality assurance across all three components.

## 🐹 Go Core — Unit & Integration Tests



```bash
cd core
go test ./...

```

---

## ⚛️ React Dashboard — Vitest



The frontend test suite uses:

* Vitest


* React Testing Library


* Mocked `vanguardClient.js`

* `ResizeObserver` mocks



Run the tests:

```bash
cd core/frontend
npx vitest run

```

**Current result:**

```text
20/20 tests passing

```

---

## 🐍 Python Toolkit — Pytest



The Python toolkit includes extensive mocking using:

* `unittest.mock`

* `responses`


This ensures CI/CD tests perform **zero real network or database operations**.

Run the tests:

```bash
cd toolkit
pytest -q

```

**Current result:**

```text
55/55 tests passing

```

---

# 📂 Codebase Structure



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
│   │      ├── Vite
│   │      ├── Tailwind
│   │      ├── Recharts
│   │      └── Lucide
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
│      ├── AI Analyst
│      ├── OSINT Sync
│      └── PDF Reports
│
└── docs/
    └── # Architecture diagrams & systemd configurations

```

---

# 🏗️ Architecture Overview



```text
                         ┌──────────────────────────┐
                         │      Linux Server        │
                         │                          │
                         │   ┌──────────────────┐   │
                         │   │  VANGUARD Core   │   │
                         │   │      (Go)        │   │
                         │   └────────┬─────────┘   │
                         │            │             │
                         │     ┌──────▼──────┐      │
                         │     │   SQLite    │      │
                         │     │    (WAL)    │      │
                         │     └──────┬──────┘      │
                         │            │             │
                         │     ┌──────▼──────┐      │
                         │     │ Python      │      │
                         │     │ Toolkit     │      │
                         │     └──────┬──────┘      │
                         │            │             │
                         └────────────┼─────────────┘
                                      │
                          ┌───────────┴───────────┐
                          │                       │
                    ┌─────▼─────┐           ┌─────▼─────┐
                    │    AI     │           │   OSINT   │
                    │  Analyst  │           │   Feeds   │
                    └───────────┘           └───────────┘

```

---

# 📊 Project Highlights



| Component | Technology |
|---|---|
| Core Engine | Go |
| REST API | Echo |
| Database | SQLite |
| Database Driver | glebarez/sqlite |
| Frontend | React |
| Build Tool | Vite |
| Styling | Tailwind CSS |
| Charts | Recharts |
| Icons | Lucide |
| AI Analysis | Anthropic / OpenAI |
| Toolkit | Python 3 + Typer |
| Service Manager | systemd |
| Firewall | UFW / iptables |
| Detection | Deterministic Rule Engine |
| Database Mode | WAL |
| Deployment | Static Linux Binary |

---

# 🔐 Security Model



VANGUARD follows a defense-in-depth approach:

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
        │  Monitor  │               │  Autopilot │
        └───────────┘               └─────┬─────┘
                                          │
                                   ┌──────▼──────┐
                                   │ Firewall    │
                                   │ Mitigation  │
                                   └─────────────┘

```

---

# 🚀 Project Status



**VANGUARD v3.0** is an actively developed security platform combining deterministic detection, automated mitigation, AI-assisted investigation, and an embedded SOC dashboard into a single edge-native architecture.

---

## 👨‍💻 Author



**Architected and developed by Masoud Hosseinpour.**

---

## ⭐ Support the Project



If VANGUARD is useful or interesting to you, consider giving the repository a ⭐ on GitHub.

```text
⭐ Star the repository
🍴 Fork the project
🐛 Report issues
💡 Suggest improvements

```

---

**VANGUARD v3.0 — Security at the Edge.**

```

```
