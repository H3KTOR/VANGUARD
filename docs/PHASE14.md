# Phase 14 — Linux Deployment, Upgrade & Release Readiness

States: **Implemented** · **Tested (Windows)** · **Verified on Linux (none)** · **Blocked**.
Nothing in this phase has been executed on Linux, with systemd, with `ufw`, in Docker, or in GitHub Actions. The installer, upgrader, unit files and CI workflow are **written and statically checked only**; the first real run is their verification.

Operator guide: [docs/install.md](install.md). Files: [`deploy/`](../deploy).

## 14.1 What was inspected, and what was wrong

| Area | Finding |
|---|---|
| Install guide | said "Go ≥ 1.21" while `core/go.mod` requires **1.25.0**; used `-http-addr :8080` (all interfaces) with an open first-run registration; the uninstall section ran `rm -rf /opt/vanguard` (deleting the database and backups) as a routine step; the toolkit cron line put an API key inline in the crontab |
| systemd unit (`docs/vanguard.service`) | **`ProtectSystem=strict` with only `/opt/vanguard/data` writable, while enforcement shells out to `sudo ufw` inside the same mount namespace** → `ufw` very probably cannot persist rules (likely `Read-only file system`); `AmbientCapabilities=CAP_NET_BIND_SERVICE` was granted though every port is > 1024; no `UMask`, no `ProtectKernelLogs/Clock/Hostname`, `RestrictNamespaces`, `SystemCallArchitectures`, `TasksMax` |
| Database files | created with the process umask (typically 0644): password hashes and incidents readable by every local account |
| Startup validation | a missing database directory surfaced as an obscure SQLite error; `-db` containing `?` would be treated as a DSN option |
| CLI | no `version` command, no way to check an install without starting it |
| CI | single OS, `go-version-file` only (declared minimum never contrasted with a current Go), no `go mod verify`/tidy check, no Windows job, no release job, no advisory vulnerability scan, no job that fails when a required job was skipped or blocked, a lab-summary only on success |
| Release | none: no version stamping, checksums or build manifest |
| `lab/` | the lab entrypoint needed two new flags after Phase 13 (bootstrap from the attacker container; `Host: victim`) |

## 14.2 Supported-platform matrix — **PROPOSED, not validated**

The repository documents Debian/Ubuntu (install guide, `apt`, `/var/log/auth.log`, `dpkg`, `ufw`) and its lab uses `debian:bookworm`. Nothing else is claimed.

| Platform | Status | Notes |
|---|---|---|
| Debian 12 (bookworm) | **primary target**; the only one the lab image uses (still unexecuted here) | full feature set |
| Debian 13 / Ubuntu 22.04 LTS / 24.04 LTS | proposed | same layout; unverified |
| RHEL-family (Rocky/Alma 9) | proposed, **reduced** | auth log is `/var/log/secure` (`-auth-log`); no `dpkg` → Package Drift disables itself gracefully; firewall is `firewalld`, not `ufw` → use the monitor-only drop-in; SELinux policy not written or tested |
| Alpine / Arch / others | unsupported (untested) | no systemd unit (OpenRC etc.) |
| Architectures | `amd64`, `arm64` cross-build with `CGO_ENABLED=0` (built here, never run) | |
| Init | systemd required for the shipped unit | |
| Windows / macOS | development only (tests run on Windows here) | host monitoring and firewall features are Linux-only |

## 14.3 Least privilege

Two shipped variants (`deploy/`):

| Variant | Privilege | `NoNewPrivileges` | Writable paths |
|---|---|---|---|
| `vanguard.service` (enforcing) | unprivileged account; **only** `sudo -n /usr/sbin/ufw` | **false** — sudo is setuid; the one option that cannot be enabled, documented in the unit | `/opt/vanguard/data` + `-/etc/ufw -/lib/ufw -/var/lib/ufw -/run/xtables.lock` (**unverified** list) |
| `vanguard-monitor-only.conf` (drop-in) | unprivileged only; no sudo, no sudoers, no `-ufw` | **true** | `/opt/vanguard/data` only |

Changes versus the previous unit: ufw state paths made writable (the `ProtectSystem=strict` defect above); `AmbientCapabilities` removed (not needed; re-add only if you DNAT low ports to the honeypot); added `ProtectKernelLogs`, `ProtectClock`, `ProtectHostname`, `RestrictNamespaces`, `SystemCallArchitectures=native`, `UMask=0077`, `TasksMax`, `LimitNOFILE`; default bind `127.0.0.1`; a **non-blocking** `ExecStartPre=-vanguard doctor …` writes the host check into the journal (remove the `-` to make `[fail]` block start once you trust it on Linux).

Deliberately **not** added because it cannot be verified here and could silently break monitoring or enforcement: `CapabilityBoundingSet=` (sudo/ufw need several), `RestrictAddressFamilies=` (iptables/nft need netlink + inet), `MemoryDenyWriteExecute=` (ufw is Python), `PrivateDevices=`. They are candidates after `systemd-analyze security` on a real host.

### Every privileged action, and who is responsible

| Action | Performed by | Operator responsibility |
|---|---|---|
| create the `vanguard` account, add to `adm` | `install.sh` (root) or by hand | `adm` grants read of *all* system logs; use an ACL on the auth log instead if that is too broad |
| directories, binary, env file, unit | `install.sh` (root) | binary is root-owned so the service cannot replace itself |
| `/etc/sudoers.d/vanguard` | `install.sh --with-ufw-sudoers` only | the rule lets the account run **any** `ufw` subcommand as root (e.g. `ufw disable`); the blast radius is the firewall |
| `ufw deny from <ip>` / `delete` | the daemon via sudo, only for validated single IPs, never for whitelisted ones | enabling `ufw`, its default policy and any other rules are yours |
| Panic Mode lockdown (`ufw default deny incoming` + allows) | the daemon, only after the confirmed two-step API call, auto-rolls back in 30 min | know the SSH port is among the essential ports |
| `systemctl enable --now` | `install.sh --enable` or you | — |

The installer never enables, disables, resets or edits `ufw`.

## 14.4 Configuration and filesystem security

- New databases are created **0600** (`database.prepareFile`; SQLite copies the mode to `-wal`/`-shm`); existing databases are not modified but a loose mode is logged and reported by `doctor`.
- `UMask=0077` in the unit covers backups and anything else the daemon creates.
- `vanguard doctor` (new, read-only): build info, platform, database directory/permissions (world-writable directory = **fail**), database existence/`integrity_check`/**schema compatibility** (newer-than-this-build = **fail**; pending additive migration = warn "back up first"), backup directory contents and permissions, disk headroom, env-file permissions (world-readable = **fail**) and JWT secret length (never printed), listen-address exposure, auth-log readability, optional `ufw status` (`-check-ufw`, read-only), optional probe of `GET /api/health`. It opens the database read-only (`mode=ro`, not `immutable`) and a test asserts it modifies and creates nothing.
- Startup refuses (exit 2) a missing database directory, `-db` that is a directory or contains URI characters, a `-backup-dir` that is a file, plus the Phase 13 checks (secret < 32 chars, non-single-IP `-admin-ip`, `-allowed-origins "*"`). `parseServeFlagsE` returns these errors so they are testable; a test feeds the shipped units' `ExecStart` lines to the real flag set, so documentation and flags cannot drift unnoticed.
- Logs: no code path was found that logs the JWT secret, Telegram token or passwords; Phase 13 added secret redaction to client-visible errors. This is a review result, not a proof.

## 14.5 Upgrade and recovery workflow

`deploy/upgrade.sh` (and the manual steps in install.md §7) — pre-checks with the **new** binary (`version`, `doctor` on real data), backup with the **current** binary + `backup verify` must say `valid`, stop, keep `vanguard.prev`, atomic replace, start, poll `/api/health`, `doctor`, and on failure restore the previous **binary** and start it only if `doctor` shows it can read the database; otherwise it prints the exact `backup restore` commands and stops. It never restores or deletes data itself. A test asserts the order *backup create → verify → stop → replace*, that the script only prints (never runs) a restore, and that it fetches nothing from the network.

Limits stated plainly: **no schema downgrade**; "rollback" is a binary swap that only works while the database is still readable by the old binary; the guaranteed path is restoring the verified backup (Phase 11 semantics, including the `-shm` sidecar uncertainty on Linux). `/api/health` proves only that the HTTP server answers. The migration step itself (GORM `AutoMigrate`, additive) is unchanged and was tested in Phases 11–12 against a real historical database.

## 14.6 Release and supply-chain hygiene

| Item | State |
|---|---|
| Dependency pinning | Go modules via `go.mod`/`go.sum`. **Observed here:** `go mod verify` → "all modules verified"; `go mod tidy` leaves `go.mod`/`go.sum` unchanged (CI now enforces both) |
| Build | `CGO_ENABLED=0 -trimpath -buildvcs=false` with `-X main.version/buildDate`; `deploy/release.sh` builds `linux/amd64` + `linux/arm64`. **Observed here:** both cross-built; `sha256sum -c SHA256SUMS` → OK; a second build on the same machine gave identical SHA-256 values (`--check-repro`) |
| Reproducibility | **only same-machine** is observed. Cross-machine/cross-toolchain reproducibility is **not claimed** until someone rebuilds elsewhere and compares |
| Signing | **none.** A checksum detects corruption, not who produced the file or whether `SHA256SUMS` was swapped. No cosign/GPG was available or configured |
| SBOM | **not generated.** No SBOM tool is installed here and its output could not be validated. `BUILD-MANIFEST.txt` contains `go version -m` (embedded module list) as a dependency listing and says so |
| Vulnerability scan | CI job `vuln` runs `govulncheck` (needs the network; advisory, never gating) and states in the job summary when it could not run. **Not run here** (no assurance); `npm audit` is likewise advisory, and 2 known frontend findings are still untriaged |
| Race tests | CI `race` job only (needs CGO); never run |
| Action pinning | actions are referenced by major tag (`@v4`/`@v5`), **not by commit SHA**; pinning needs network access to resolve SHAs and is a recommended hardening |
| Downloads | nothing downloads or executes remote scripts; `install.sh`/`upgrade.sh`/`release.sh` fetch nothing (tested) |
| External services | none required for operation; CI uses GitHub only; the Telegram notifier and toolkit remain optional |

## 14.7 CI and platform matrix (`.github/workflows/ci.yml`, **never executed**)

| Job | Category | Gates? |
|---|---|---|
| `static` | gofmt, `go vet`, `go mod verify` + tidy diff, CGO-free cross builds, `bash -n` on `deploy/*.sh` and `lab/*.sh` | yes |
| `go-test` (matrix: Go from `go.mod` = **declared minimum**, and `stable`) | unit, Linux-only tests included | yes |
| `go-test-windows` | unit on Windows (what was run in development) | yes |
| `race` | `go test -race` with CGO | yes |
| `frontend` | Vitest + Vite build (+ advisory `npm audit`) | yes (audit: no) |
| `lab` | Docker lab, `run-all.sh --teardown`; exit 1 = fail, **exit 3 = blocked → job fails** | yes |
| `release-check` | unsigned artifacts, rebuild comparison, checksum verification | yes |
| `vuln` | `govulncheck` | **advisory** |
| `report` | `tools/valreport` per platform; skipped tests listed as skipped, blocked checks listed as not run | informational |
| `gate` | fails unless **every** required job's result is exactly `success` (skipped / cancelled / failed all fail it) | the single status to require |

Platform-specific tests call `t.Skip` with a reason; `valreport` counts them separately and never as passes. The workflow's YAML syntax was parsed once with `yaml.v3` (this caught and fixed one invalid plain scalar); **semantics, expression syntax and action inputs are unverified.**

## 14.8 Release validation checklist (do these on Linux before calling a release "verified")

1. `git status` clean; tag; `make build`; `core/vanguard version` shows the tag and `CGO_ENABLED=0`.
2. CI `gate` green on the tagged commit (all required jobs `success`, none skipped).
3. `bash lab/run-all.sh --teardown` → exit 0 with every suite `pass`; archive `lab/results/`.
4. `cd core && CGO_ENABLED=1 go test -race ./...` → no race reports.
5. On Debian 12, as a clean VM: `sudo deploy/install.sh --binary … --dry-run`, then for real; `systemd-analyze verify`; `systemd-analyze security vanguard`; start; `doctor`; create the first admin through a tunnel; confirm the dashboard shows runtime health.
6. Enforcing variant: with `ufw` enabled in a VM, `POST /api/firewall/block` for a test address → `sudo ufw status` shows the rule (**this verifies the `ReadWritePaths` list**); unban removes it; restart the service and confirm re-applied bans and that simulated bans are not applied.
7. Monitor-only variant: same without sudo; bans recorded, nothing in `ufw status`.
8. Upgrade drill: install the previous release, create data, run `deploy/upgrade.sh`; then force a failure (bad binary) and confirm the printed recovery restores the pre-upgrade backup.
9. Backup/restore drill including the `-shm` sidecar behaviour and the in-use probe against the **running** daemon (Phase 11 open items).
10. `deploy/release.sh --check-repro` on two different machines produce identical `SHA256SUMS` before writing the word "reproducible".
11. `govulncheck ./...` and `npm audit` reviewed; open findings recorded.
12. Sign the artifacts with your own key if you need authenticity; none of the above provides it.

## 14.9 Tests (this phase)

`cmd/vanguard`: unit-file properties (unprivileged user, hardening set, documented `NoNewPrivileges`, no ambient caps, non-blocking pre-check), **ExecStart lines parse with the real flag set** (both units), monitor-only drop-in removes privilege (clears `ExecStart`/`ReadWritePaths`), env example carries no values, deploy-script syntax + safety properties (no network fetch, no firewall change, never overwrites, backup-before-replace order) [**needs `bash`**: skipped under plain PowerShell, passed under Git-bash], doctor (10 tests: fresh host, missing directory, read-only against a live DB, legacy schema = warn, newer schema = fail, corrupt file never ok, secret never printed + permissions, listen advice, health probe, backups, POSIX perms), version info, startup path validation, `parseServeFlagsE` rejects every bad value. `database`: new files private / existing untouched [POSIX only]. `backup`: `InspectLive` is exercised through doctor.

## 14.10 Results (Windows, Go 1.27.0; no Linux, systemd, ufw, Docker, CGO, GitHub runner)

| Command | Result |
|---|---|
| `gofmt -l .`; `GOOS=linux go vet ./...` | clean; clean |
| `go test -json ./...` → `tools/valreport` | **666 passed, 0 failed, 16 skipped** (Phase 13: 648/0/13). Skips (**not passes**): 10 Unix-permission `hostsec`, tail line-delivery ×2 (Linux only), POSIX-permission ×3 (backup, doctor, database new-file mode), deploy-script test when `bash` is not on `PATH` |
| `go test ./cmd/vanguard -run DeployScripts` under Git-bash | pass |
| `npx vitest run`; `npx vite build` | 67 pass (7 files); OK |
| `bash -n deploy/*.sh` | OK |
| `deploy/install.sh --dry-run … --with-ufw-sudoers`; `deploy/upgrade.sh --dry-run` (happy path and a `doctor`-failure abort) under Git-bash | printed the expected plan; the abort path stopped before changing anything |
| `deploy/release.sh --targets "linux/amd64 linux/arm64" --check-repro`; `sha256sum -c` | built both; checksums OK; same-machine rebuild identical |
| `go mod verify`; `go mod tidy` | "all modules verified"; no change to `go.mod`/`go.sum` |
| `.github/workflows/ci.yml` parsed with `yaml.v3` | 10 jobs, dependency graph as designed (after one YAML fix) |
| `make` | **not available here**: the new Makefile targets (`release`, `check-deploy`, version `-X`) were not run |

## 14.11 Compatibility, migration and remaining risks

1. **Default bind** is `127.0.0.1:8080` (Phase 13) — the shipped unit now says so explicitly; an installed older unit keeps `:8080` until you replace it (`install.sh` writes `vanguard.service.new`, never overwrites).
2. The new unit's `ReadWritePaths`, `SupplementaryGroups=adm` and the whole hardening set are **unverified against a real systemd**; a directive your systemd version does not know is ignored with a warning, but a path the unit needs and does not list will fail at runtime.
3. `deploy/*.sh` run as root: read them (they are short) and use `--dry-run` first. They were never run on Linux; `useradd`, `usermod`, `runuser`, `visudo` flags are standard but unexercised.
4. `docs/vanguard.service` moved to `deploy/vanguard.service` (git rename). Any script that copied the old path must be updated.
5. The existing-database permission policy (never silently chmod) means installs created before this release keep whatever mode they have until you run `chmod`; `doctor` tells you.
6. CI changes the required status to the `gate` job; branch protection that listed the old job names must be updated.
7. The Docker lab entrypoint change (`-allow-remote-bootstrap -allowed-hosts=victim`) is untested; lab scripts that reach the API by another DNS name need it added.
8. Not done: package managers (`.deb`/`.rpm`), SELinux/AppArmor profiles, signing/SBOM, a reverse-proxy sample config, automatic migration dry-run (the schema diff in `doctor` is the closest), non-systemd init.

## Acceptance

| Criterion | State |
|---|---|
| Linux deployment instructions reflect the actual application | rewritten from the code (flags verified by test); unexecuted on Linux |
| Least privilege applied where compatible and testable | two variants; directives checked statically; runtime behaviour unverified |
| Installation does not silently destroy existing state | enforced by construction and by tests on the script text; dry-run exercised; real run not performed |
| Upgrade and recovery explicit | scripted + documented; limits (no downgrade) stated |
| CI reports unsupported and blocked checks accurately | designed so; never executed |
| Release claims backed by validation | only what is listed as observed in §14.6/§14.10 |
| No cloud/external service mandatory | none added |

**Status: Implemented — Verification Pending.**
