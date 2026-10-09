# VANGUARD — Linux Install, Upgrade & Recovery Guide

How to build VANGUARD, run it as an unprivileged systemd service, keep operator
data safe across upgrades, and recover when something goes wrong.

> **Honesty box.** Everything in `deploy/` and this guide was written and
> syntax-checked on Windows. **None of it has been executed on a real Linux
> host, systemd or `ufw`.** Every privileged step is marked, `deploy/install.sh`
> and `deploy/upgrade.sh` support `--dry-run`, and `vanguard doctor` checks the
> host read-only. Treat the first install on a real machine as the
> verification, and report what differs (checklist: [docs/PHASE14.md](PHASE14.md)).

Supported platforms (proposed, not yet validated on each): see the matrix in
[docs/PHASE14.md §14.1](PHASE14.md).

---

## 0. Prerequisites

```bash
# Debian / Ubuntu shown; adjust the package manager for other distributions.
sudo apt update
sudo apt install -y git nodejs npm ufw sudo        # ufw/sudo only if you want firewall enforcement
# Go >= 1.25 (the version in core/go.mod) is required; Debian/Ubuntu packages are often older.
# Install a current Go from https://go.dev/dl/ and verify its published checksum yourself.
go version
node --version          # Node 20 is what CI uses
```

Python (`python3`, `python3-venv`) is needed only for the optional toolkit (§9).

---

## 1. Build (or obtain) the binary

```bash
git clone <your-vanguard-repo-url> vanguard-src && cd vanguard-src
make build                         # builds the dashboard, then the Go binary with it embedded
./core/vanguard version            # shows version, Go version, commit, CGO_ENABLED=0
```

Build it yourself from source you reviewed, or verify a release against its
published `SHA256SUMS` (a checksum detects corruption, not who built the file;
releases are **unsigned**, see PHASE14.md §14.5). `make release` / `deploy/release.sh`
produces unsigned cross-compiled artifacts plus a build manifest.

---

## 2. Install — recommended: the install script (dry-run first)

```bash
sudo deploy/install.sh --binary core/vanguard --dry-run      # prints every step, changes nothing
sudo deploy/install.sh --binary core/vanguard                # does it
```

What it does, and the privileged actions it takes (all of them, nothing else):

| Privileged action | Why | Never overwrites |
|---|---|---|
| `useradd --system vanguard` (no login shell), add to group `adm` | unprivileged service account; read `/var/log/auth.log` | an existing account is kept as is |
| create `/opt/vanguard/data` (0700 vanguard) and `/etc/vanguard` (0750 root:vanguard) | data and secrets locations | existing directories are untouched |
| install `/usr/local/bin/vanguard` (root:root 0755) | the daemon | **refuses** if one exists (use `upgrade.sh`) |
| write `/etc/vanguard/vanguard.env` (0600) with a generated secret | JWT signing key; never printed | **only if absent** |
| install `/etc/systemd/system/vanguard.service` | the unit | if different, writes `vanguard.service.new` for you to diff |
| `--with-ufw-sudoers` (opt-in): `/etc/sudoers.d/vanguard` | lets the account run **only** `/usr/sbin/ufw`; validated with `visudo -c` first | existing file untouched |
| `--enable` (opt-in): `systemctl enable --now vanguard` | start at boot | — |

It does **not** download anything, start the service unless asked, or change
`ufw` in any way. Whether `ufw` is enabled and what rules it has remain yours.

### Manual equivalent (if you do not want to run the script)

```bash
sudo useradd --system --home-dir /opt/vanguard --shell /usr/sbin/nologin vanguard
sudo usermod -aG adm vanguard
sudo install -d -m 0700 -o vanguard -g vanguard /opt/vanguard/data
sudo install -d -m 0750 -o root -g vanguard /etc/vanguard
sudo install -m 0755 -o root -g root core/vanguard /usr/local/bin/vanguard
( umask 077; printf 'VANGUARD_JWT_SECRET=%s\n' "$(openssl rand -hex 32)" | sudo tee /etc/vanguard/vanguard.env >/dev/null )
sudo chown vanguard:vanguard /etc/vanguard/vanguard.env && sudo chmod 0600 /etc/vanguard/vanguard.env
sudo install -m 0644 deploy/vanguard.service /etc/systemd/system/vanguard.service
sudo systemctl daemon-reload
```

---

## 3. Privilege model — pick one

**A. Monitor-only (least privilege, recommended to start).** Detection,
incidents, dashboard and honeypot run as the unprivileged account.
Autopilot still decides on bans and records them, but **nothing is blocked at
the OS level**. No sudo, no setuid, `NoNewPrivileges=true`:

```bash
sudo install -D -m 0644 deploy/vanguard-monitor-only.conf /etc/systemd/system/vanguard.service.d/monitor-only.conf
sudo systemctl daemon-reload
```

**B. Enforcing (`-ufw -ufw-sudo`).** Bans become real `ufw deny from <ip>` rules.
This needs a narrowly scoped sudo rule and therefore `NoNewPrivileges=false`
(sudo is setuid) — the one hardening option this variant cannot enable:

```bash
echo 'vanguard ALL=(root) NOPASSWD: /usr/sbin/ufw' | sudo tee /etc/sudoers.d/vanguard >/dev/null
sudo chmod 0440 /etc/sudoers.d/vanguard && sudo visudo -c
sudo ufw status            # enable ufw yourself if you intend to enforce: `sudo ufw enable` is your decision
```

The shipped unit also lists the `ufw` state directories as writable
(`/etc/ufw /lib/ufw /var/lib/ufw /run/xtables.lock`) because `sudo ufw` runs
inside the unit's read-only mount namespace. **That list is unverified.** If
bans fail with `Read-only file system` in `journalctl -u vanguard`, extend
`ReadWritePaths=` (and tell us which path was missing).

Whatever you choose: bans never apply to the fail-safe whitelist (loopback and
`VANGUARD_ADMIN_IPS`), and Panic Mode keeps its confirmation and preview.

---

## 4. Configuration, secrets and file permissions

| Item | Expected | Why |
|---|---|---|
| `/etc/vanguard/vanguard.env` | `0600 vanguard:vanguard` | holds `VANGUARD_JWT_SECRET` (≥ 32 chars; the daemon refuses shorter), optional Telegram token |
| `/opt/vanguard/data` | `0700 vanguard` | SQLite database (password hashes, incidents), backups |
| `vanguard.db`, `-wal`, `-shm`, `backups/*` | `0600` | new files are created private (`UMask=0077`; the daemon creates a new database 0600). An **existing** database's mode is never changed for you; `doctor` warns |
| `/usr/local/bin/vanguard` | `root:root 0755` | the service account must not be able to replace its own binary |
| `/etc/sudoers.d/vanguard` | `0440 root` | only `/usr/sbin/ufw` |

Check all of this, read-only, any time:

```bash
sudo -u vanguard /usr/local/bin/vanguard doctor \
    -db /opt/vanguard/data/vanguard.db -env-file /etc/vanguard/vanguard.env \
    [-check-ufw -ufw-sudo] [-health-url http://127.0.0.1:8080]
```

`doctor` never writes to the database, never changes a permission, never
touches the firewall (the `ufw` probe is opt-in and only runs `ufw status`),
and never prints a secret. Exit 0 = no `[fail]` (warnings are advice); exit 1 =
fix the `[fail]` lines first.

**Network exposure.** The daemon listens on `127.0.0.1:8080` and speaks plain
HTTP. To reach it remotely use an SSH tunnel (`ssh -L 8080:127.0.0.1:8080 host`)
or a TLS reverse proxy, and list the proxy's public name:

```
# /etc/vanguard/vanguard.env
VANGUARD_ALLOWED_HOSTS=vanguard.example.com
```

(IP literals and `localhost` always work; any other `Host` is refused to defeat
DNS rebinding.) Do not open `:8080` to the internet. First-run admin creation
is only accepted from the host itself, so **create the first admin through the
tunnel or on the machine**.

---

## 5. Start and verify

```bash
sudo systemctl enable --now vanguard
sudo systemctl status vanguard
sudo journalctl -u vanguard -n 50 --no-pager      # includes the non-blocking `doctor` output
systemd-analyze verify /etc/systemd/system/vanguard.service
systemd-analyze security vanguard                  # review the exposure score; it is advice, not a pass/fail
curl -s http://127.0.0.1:8080/api/health           # {"status":"ok",...}  proves the HTTP server is up, nothing more
```

Open the dashboard through your tunnel/proxy, create the first admin, then check
**Runtime health** in the dashboard (or `GET /api/health/runtime` while signed
in): a log source that is missing, a failed detector or a lost incident is shown
there, not in `/api/health`.

---

## 6. Service troubleshooting

| Symptom | Likely cause → what to run |
|---|---|
| unit `failed` immediately | `journalctl -u vanguard -n 50`. Startup refuses bad configuration with exit 2: JWT secret < 32 chars, `-admin-ip` that is not a single IP, `-allowed-origins "*"`, missing database directory |
| `doctor` says database directory missing | `sudo install -d -m 0700 -o vanguard -g vanguard /opt/vanguard/data` |
| login keeps returning 429 | repeated failures from one address are throttled for 15 min; sessions already signed in are unaffected |
| `403 this Host is not allowed` | reached through a DNS name: add it to `VANGUARD_ALLOWED_HOSTS` |
| first-run says "only allowed from the host itself" | create the admin via `curl` on the host or an SSH tunnel (or start once with `-allow-remote-bootstrap`) |
| bans appear in the dashboard but `ufw status` shows no rule | monitor-only mode, or `-ufw` flags missing, or `sudo -u vanguard sudo -n ufw status` fails, or `ReadWritePaths` too narrow (see §3) → `doctor -check-ufw -ufw-sudo` |
| SSH brute force never detected | `doctor` → `auth_log` warns: the account cannot read `/var/log/auth.log` (group `adm`); health shows the log source as degraded/not observed |
| every session ends at each restart | `VANGUARD_JWT_SECRET` missing from the env file |
| dashboard 404 "build not found" | built with `make build-go` before the dashboard existed: run `make build` |
| `database ... newer VANGUARD` warning/doctor fail | the database was written by a newer build; downgrade is unsupported → run a build at least that new, or restore an older verified backup |

---

## 7. Upgrade (with a verified backup first)

```bash
git pull && make build
sudo deploy/upgrade.sh --binary core/vanguard --dry-run     # read the plan
sudo deploy/upgrade.sh --binary core/vanguard
```

The script: (1) requires the **new** binary to run and pass `doctor` against
your real data, (2) creates a backup with the **current** binary and requires
`backup verify` to say `valid`, (3) stops the service, keeps the old binary as
`vanguard.prev`, atomically installs the new one, (4) starts it and waits for
`/api/health`, (5) on failure puts the previous **binary** back and starts it
only if it can still read the database. It never restores or deletes a
database itself. Your `/etc/vanguard/vanguard.env`, unit overrides and data are
not touched (a changed shipped unit is **not** installed over yours — diff
`deploy/vanguard.service` against `/etc/systemd/system/vanguard.service`).

Manual equivalent:

```bash
sudo -u vanguard vanguard backup create -db /opt/vanguard/data/vanguard.db -label preupg
sudo -u vanguard vanguard backup verify -db /opt/vanguard/data/vanguard.db -name <name printed above>
sudo systemctl stop vanguard
sudo cp -p /usr/local/bin/vanguard /usr/local/bin/vanguard.prev
sudo install -m 0755 core/vanguard /usr/local/bin/vanguard
sudo systemctl start vanguard && curl -s http://127.0.0.1:8080/api/health
```

**What "rollback" means here.** Schema changes are additive and automatic at
start; there is **no schema downgrade**. After the new version has opened the
database, the previous binary may refuse it. The only guaranteed way back is
restoring the verified pre-upgrade backup. Putting the old binary back is
only a rollback if the old binary can still read the migrated database
(`doctor` tells you).

### Recovery from a failed upgrade (explicit, operator-driven)

```bash
sudo systemctl stop vanguard
sudo install -m 0755 /usr/local/bin/vanguard.prev /usr/local/bin/vanguard
sudo -u vanguard vanguard backup restore -db /opt/vanguard/data/vanguard.db -name <preupg backup>            # preview: changes nothing
sudo -u vanguard vanguard backup restore -db /opt/vanguard/data/vanguard.db -name <preupg backup> -confirm   # replaces the database; the old one is kept as *.pre-restore-*
sudo systemctl start vanguard
sudo -u vanguard vanguard doctor -db /opt/vanguard/data/vanguard.db -env-file /etc/vanguard/vanguard.env -health-url http://127.0.0.1:8080
```

Details, limits and the integrity story for backups: [docs/PHASE11.md](PHASE11.md).
A restored or restored-then-migrated database starts with **Panic Mode off** and
re-applies stored (non-simulated) bans to `ufw` at start.

---

## 8. Uninstall (does not delete your data unless you do)

```bash
sudo systemctl disable --now vanguard
sudo rm -f /etc/systemd/system/vanguard.service /etc/sudoers.d/vanguard
sudo rm -rf /etc/systemd/system/vanguard.service.d
sudo systemctl daemon-reload
sudo rm -f /usr/local/bin/vanguard /usr/local/bin/vanguard.prev
# DATA IS LEFT IN PLACE: /opt/vanguard/data (database, backups) and /etc/vanguard (secrets).
# Back it up first if you might want it, then, deliberately:
#   sudo rm -rf /opt/vanguard /etc/vanguard && sudo userdel vanguard
```

Removing the unit does **not** remove `ufw` rules VANGUARD added; list them with
`sudo ufw status numbered` and delete the ones you want gone.

---

## 9. Optional: the Python toolkit on a schedule (cron)

The toolkit is an ephemeral CLI (threat-intel sync, AI analysis, PDF reports), not a service.

```bash
sudo mkdir -p /opt/vanguard/toolkit && sudo cp -r toolkit/* /opt/vanguard/toolkit/ && sudo chown -R vanguard:vanguard /opt/vanguard/toolkit
cd /opt/vanguard/toolkit
sudo -u vanguard python3 -m venv .venv
sudo -u vanguard .venv/bin/pip install -r requirements.txt
sudo -u vanguard mkdir -p /opt/vanguard/data/reports
sudo -u vanguard crontab -e
```

```cron
0 */6 * * * cd /opt/vanguard/toolkit && VANGUARD_DB_PATH=/opt/vanguard/data/vanguard.db .venv/bin/python3 main.py sync >> sync.log 2>&1
0 6 * * *   cd /opt/vanguard/toolkit && VANGUARD_DB_PATH=/opt/vanguard/data/vanguard.db .venv/bin/python3 main.py report --output /opt/vanguard/data/reports/soc-$(date +\%F).pdf >> report.log 2>&1
```

Put API keys for `analyze` in a `0600` file the cron line sources
(`set -a; . /etc/vanguard/toolkit.env; set +a`), **not** inline in the crontab
(crontabs are readable and keys end up in process listings).
