# VANGUARD v3.0 — Production Install Guide (systemd)

Concise, copy-pasteable steps to build VANGUARD and run it as a systemd
service on a Debian/Ubuntu-family Linux host. Adjust package manager
commands (`apt`) for other distros as needed.

---

## 0. Prerequisites

```bash
sudo apt update
sudo apt install -y golang-go nodejs npm python3 python3-pip python3-venv ufw sudo git

# Go >= 1.21 and Node >= 18 are required. Check versions:
go version
node --version
```

---

## 1. Build the Go binary (with the React dashboard embedded)

```bash
git clone <your-vanguard-repo-url> vanguard-src
cd vanguard-src

# make build chains: (1) npm install + npm run build for core/frontend,
# writing the compiled dashboard into core/cmd/vanguard/dist, then
# (2) go build, which embeds that dist/ directory into the binary via
# //go:embed all:dist (see core/cmd/vanguard/frontend.go).
make build

# Verify the binary was produced and the dashboard is embedded:
ls -lh core/vanguard
./core/vanguard help
```

If you only need to rebuild the Go binary after the frontend has already
been built once, `make build-go` skips the npm step.

---

## 2. Create the dedicated `vanguard` system user

Running as an unprivileged, dedicated user (not root) limits blast radius;
firewall enforcement is delegated to a narrowly-scoped `sudo ufw` rule
instead of running the whole daemon as root.

```bash
sudo useradd --system --create-home --home-dir /opt/vanguard --shell /usr/sbin/nologin vanguard

# The daemon needs to read /var/log/auth.log for SSH brute-force
# detection -- the `adm` group can read system logs on Debian/Ubuntu
# without granting broader privileges.
sudo usermod -aG adm vanguard
```

---

## 3. Install the binary and toolkit

```bash
# Go binary
sudo install -m 0755 -o root -g root core/vanguard /usr/local/bin/vanguard

# Directory layout
sudo mkdir -p /opt/vanguard/data /opt/vanguard/toolkit /etc/vanguard
sudo chown -R vanguard:vanguard /opt/vanguard

# Python toolkit (ephemeral CLI, run via cron/on demand -- NOT a systemd service)
sudo cp -r toolkit/* /opt/vanguard/toolkit/
cd /opt/vanguard/toolkit
sudo -u vanguard python3 -m venv .venv
sudo -u vanguard .venv/bin/pip install --upgrade pip
sudo -u vanguard .venv/bin/pip install -r requirements.txt
```

---

## 4. Configure the initial `VANGUARD_JWT_SECRET`

The dashboard signs session JWTs with this HMAC secret. If it isn't set,
`vanguard serve` generates a random one on every startup — every logged-in
session is invalidated on each restart, which is unacceptable in
production. Generate a stable secret once and store it out of `ps`/shell-
history reach:

```bash
# Generate a cryptographically random 256-bit secret:
VANGUARD_SECRET=$(openssl rand -hex 32)

# Write the env file systemd will load (see docs/vanguard.service's
# EnvironmentFile directive). Keep this file at 0600, owned by vanguard.
sudo tee /etc/vanguard/vanguard.env > /dev/null <<EOF
VANGUARD_JWT_SECRET=${VANGUARD_SECRET}
# Optional: comma-separated IPs Autopilot must NEVER auto-ban (e.g. your
# own admin/office IP) -- uncomment and edit:
# VANGUARD_ADMIN_IPS=203.0.113.10,203.0.113.11
EOF

sudo chown vanguard:vanguard /etc/vanguard/vanguard.env
sudo chmod 0600 /etc/vanguard/vanguard.env
unset VANGUARD_SECRET   # don't leave the plaintext secret in your shell history
```

---

## 5. Grant the scoped `sudo ufw` rule

`vanguard serve -ufw -ufw-sudo` shells out to `sudo ufw` to enforce bans at
the OS firewall level. Restrict `vanguard`'s sudo rights to exactly that
binary, nothing else:

```bash
echo 'vanguard ALL=(root) NOPASSWD: /usr/sbin/ufw' | sudo tee /etc/sudoers.d/vanguard
sudo chmod 0440 /etc/sudoers.d/vanguard
sudo visudo -c   # validates syntax before it takes effect

# Ensure ufw itself is enabled (if not already):
sudo ufw status
sudo ufw enable
```

---

## 6. Install and start the systemd service

```bash
sudo cp docs/vanguard.service /etc/systemd/system/vanguard.service
sudo systemctl daemon-reload
sudo systemctl enable --now vanguard

# Verify it's running:
sudo systemctl status vanguard
sudo journalctl -u vanguard -f --no-pager -n 50
```

Expected healthy log lines (mirrors what `make build && ./core/vanguard
serve` prints in dev):

```
[serve] VANGUARD Core starting (db=/opt/vanguard/data/vanguard.db http=:8080)
[database] opened /opt/vanguard/data/vanguard.db (WAL) and migrated 4 models
[serve] firewall executor: real ufw CLI (sudo)
[serve] VANGUARD Core is up. Press Ctrl+C (or send SIGTERM) to stop.
[serve] REST API + dashboard listening on :8080
```

---

## 7. Open the dashboard and bootstrap the admin account

```bash
curl -s http://localhost:8080/api/health
# {"status":"ok", ...}
```

Visit `http://<your-host>:8080/` in a browser (or put it behind a reverse
proxy/TLS terminator — VANGUARD itself serves plain HTTP). On first run,
with an empty `users` table, the login screen shows an admin-bootstrap
form instead of a login form; create the first admin account there.

> **Reverse proxy note**: VANGUARD does not terminate TLS itself. For a
> public-facing deployment, put Nginx/Caddy/Traefik in front of `:8080`
> with a real certificate, and consider firewalling `:8080` to localhost
> only (`ufw deny 8080` + proxy on 443) so the dashboard is never reachable
> unproxied.

---

## 8. Set up the Python toolkit on a schedule (cron)

The toolkit is deliberately **not** a systemd service — it's an ephemeral,
zero-idle-RAM CLI meant to run periodically and exit. A typical crontab
for the `vanguard` user:

```bash
sudo -u vanguard crontab -e
```

```cron
# Sync OSINT threat-intel bans every 6 hours
0 */6 * * * cd /opt/vanguard/toolkit && VANGUARD_DB_PATH=/opt/vanguard/data/vanguard.db .venv/bin/python3 main.py sync >> /opt/vanguard/toolkit/sync.log 2>&1

# AI forensic analysis of new incidents every hour (requires an API key --
# add ANTHROPIC_API_KEY or OPENAI_API_KEY to /etc/vanguard/vanguard.env
# and source it, or export it directly in this crontab line)
0 * * * * cd /opt/vanguard/toolkit && VANGUARD_DB_PATH=/opt/vanguard/data/vanguard.db ANTHROPIC_API_KEY=sk-ant-... .venv/bin/python3 main.py analyze >> /opt/vanguard/toolkit/analyze.log 2>&1

# Daily SOC PDF report at 06:00
0 6 * * * cd /opt/vanguard/toolkit && VANGUARD_DB_PATH=/opt/vanguard/data/vanguard.db .venv/bin/python3 main.py report --output /opt/vanguard/data/reports/soc-$(date +\%F).pdf >> /opt/vanguard/toolkit/report.log 2>&1
```

```bash
sudo -u vanguard mkdir -p /opt/vanguard/data/reports
```

Run any toolkit command manually to verify it works before relying on cron:

```bash
cd /opt/vanguard/toolkit
sudo -u vanguard env VANGUARD_DB_PATH=/opt/vanguard/data/vanguard.db .venv/bin/python3 main.py sync --dry-run
```

---

## Upgrading

```bash
cd vanguard-src && git pull
make build
sudo systemctl stop vanguard
sudo install -m 0755 core/vanguard /usr/local/bin/vanguard
sudo cp -r toolkit/* /opt/vanguard/toolkit/   # if toolkit files changed
sudo systemctl start vanguard
sudo systemctl status vanguard
```

## Uninstalling

```bash
sudo systemctl disable --now vanguard
sudo rm /etc/systemd/system/vanguard.service
sudo systemctl daemon-reload
sudo rm -rf /opt/vanguard /etc/vanguard /etc/sudoers.d/vanguard
sudo userdel vanguard
sudo rm /usr/local/bin/vanguard
```

## Troubleshooting

| Symptom | Fix |
|---|---|
| `systemctl status vanguard` shows `failed` immediately | `journalctl -u vanguard -n 50` — usually a missing `/opt/vanguard/data` dir or bad `EnvironmentFile` path/permissions |
| Dashboard shows "dashboard build not found" 404 | The binary was built before `npm run build` ever ran, or `core/cmd/vanguard/dist` was empty at `go build` time — rerun `make build` (not `make build-go`) |
| Every login is invalidated on restart | `VANGUARD_JWT_SECRET` isn't set in `/etc/vanguard/vanguard.env` — see step 4 |
| Bans aren't actually enforced at the OS level | Confirm `-ufw -ufw-sudo` flags are present in the unit and `sudo -u vanguard sudo ufw status` works without a password prompt (step 5) |
| `sudo: a password is required` in journalctl | The `/etc/sudoers.d/vanguard` rule is missing/misconfigured — rerun step 5 and `sudo visudo -c` |
